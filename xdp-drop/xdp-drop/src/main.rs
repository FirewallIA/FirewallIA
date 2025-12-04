use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::{CommandFactory, Parser};
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tonic::{transport::Server, Request, Response};
use xdp_drop_common::{IpPort, PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

// modules firewall et google
pub mod firewall {
    tonic::include_proto!("firewall");
}
pub mod google {
    pub mod protobuf {
        tonic::include_proto!("google.protobuf");
    }
}

use crate::firewall::firewall_service_server::{FirewallService, FirewallServiceServer};
use crate::firewall::{
    CreateRuleRequest, CreateRuleResponse, DeleteRuleRequest, DeleteRuleResponse, FirewallStatus,
    RuleInfo, RuleListResponse,
};
use crate::google::protobuf::Empty;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'i', long = "int")]
    iface: String,
}

// utilitaire pour convertir le protocole
fn protocol_to_u8(protocol_str: &Option<String>) -> u8 {
    match protocol_str {
        Some(s) => match s.to_lowercase().as_str() {
            "tcp" => PROTO_TCP,
            "udp" => PROTO_UDP,
            "icmp" => PROTO_ICMP,
            "any" | "*" | "" => PROTO_ANY,
            _ => PROTO_ANY,
        },
        None => PROTO_ANY,
    }
}

fn validate_args(opt: &Opt) {
    if opt.iface.trim().is_empty() {
        let mut cmd = Opt::command();
        eprintln!("Erreur : l'interface réseau est requise.\n");
        cmd.print_help().unwrap();
        std::process::exit(1);
    }
}

pub struct MyFirewallService {
    db_client: Arc<tokio_postgres::Client>,
    // Utilisation de MapData (owned) pour éviter les problèmes de durée de vie (lifetime)
    blocklist: Arc<tokio::sync::Mutex<HashMap<aya::maps::MapData, IpPort, u32>>>,
}

async fn fetch_and_format_rules_from_db(
    db_client: &Arc<tokio_postgres::Client>,
) -> Result<Vec<RuleInfo>, anyhow::Error> {
    let rows = db_client
        .query(
            "SELECT id, name, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules",
            &[],
        )
        .await
        .context("Erreur lors de l'exécution du SELECT sur rules")?;

    let mut rule_infos = Vec::new();
    for row in rows {
        let id: i32 = row.get("id");
        let name_str: String = row.get("name");
        let source_ip_str: String = row.get("source_ip");
        let dest_ip_str: String = row.get("dest_ip");
        let source_port_opt: Option<i32> = row.get("source_port");
        let dest_port_opt: Option<i32> = row.get("dest_port");
        let action_str: String = row.get("action");
        let protocol_opt: Option<String> = row.get("protocol");
        let usage_count_val: i32 = row.get("usage_count");

        rule_infos.push(RuleInfo {
            id,
            name: name_str, // Correction syntaxe (c'était name = name_str)
            source_ip: source_ip_str,
            dest_ip: dest_ip_str,
            source_port: source_port_opt.map_or("*".to_string(), |p| p.to_string()),
            dest_port: dest_port_opt.map_or("*".to_string(), |p| p.to_string()),
            action: action_str,
            protocol: protocol_opt.unwrap_or_else(|| "any".to_string()),
            usage_count: usage_count_val,
        });
    }
    Ok(rule_infos)
}

#[tonic::async_trait]
impl FirewallService for MyFirewallService {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<FirewallStatus>, tonic::Status> {
        info!("gRPC: Appel de GetStatus reçu");
        Ok(Response::new(FirewallStatus {
            status: "UP".to_string(),
        }))
    }

    async fn list_rules(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RuleListResponse>, tonic::Status> {
        info!("gRPC: Appel de ListRules reçu");
        match fetch_and_format_rules_from_db(&self.db_client).await {
            Ok(rules) => Ok(Response::new(RuleListResponse { rules })),
            Err(e) => {
                log::error!("Erreur lors de la récupération des règles pour gRPC: {}", e);
                Err(tonic::Status::internal(format!(
                    "Échec de la récupération des règles: {}",
                    e
                )))
            }
        }
    }

    async fn create_rule(
        &self,
        request: Request<CreateRuleRequest>,
    ) -> Result<Response<CreateRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let rule_to_create = req_data
            .rule
            .ok_or_else(|| tonic::Status::invalid_argument("Données de règle manquantes"))?;

        // --- 1. Validation des entrées ---
        if rule_to_create.source_ip.is_empty() || rule_to_create.dest_ip.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "Les adresses IP source et destination ne peuvent pas être vides.",
            ));
        }
        let action_str = rule_to_create.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(tonic::Status::invalid_argument(
                "Action invalide. Doit être 'allow' ou 'deny'.",
            ));
        }

        // Parsing des ports pour la DB (i32) et pour BPF (u16)
        let source_port_db: Option<i32> = rule_to_create.source_port.parse().ok();
        let dest_port_db: Option<i32> = rule_to_create.dest_port.parse().ok();
        let dest_port_u16 = dest_port_db.unwrap_or(0) as u16;

        // --- 2. Insertion dans la Base de Données ---
        // CORRECTION MAJEURE ICI : Ajout du paramètre $7 et insertion correcte de `name`
        let created_rule_id: i32 = self.db_client.query_one(
            "INSERT INTO rules (name, source_ip, dest_ip, source_port, dest_port, action, protocol) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            &[
                &rule_to_create.name,        // $1
                &rule_to_create.source_ip,   // $2
                &rule_to_create.dest_ip,     // $3
                &source_port_db,             // $4
                &dest_port_db,               // $5
                &action_str,                 // $6
                &rule_to_create.protocol.to_uppercase() // $7
            ],
        ).await.map_err(|e| {
            log::error!("Erreur insertion DB: {}", e);
            tonic::Status::internal(format!("Échec création règle DB: {}", e))
        })?.get(0);

        // --- 3. MISE A JOUR A CHAUD DU BPF ---

        // a. Parsing des IPs (gestion de "any")
        let ip_src = if rule_to_create.source_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            rule_to_create
                .source_ip
                .parse()
                .map_err(|_| tonic::Status::invalid_argument("IP Source invalide"))?
        };

        let ip_dst = if rule_to_create.dest_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            rule_to_create
                .dest_ip
                .parse()
                .map_err(|_| tonic::Status::invalid_argument("IP Dest invalide"))?
        };

        // b. Construction de la clé
        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: dest_port_u16.to_be(),
            protocol: protocol_to_u8(&Some(rule_to_create.protocol.clone())),
            _pad: 0,
        };

        // c. Détermination de l'action (1 = DENY, 2 = ALLOW)
        const ACTION_DENY: u32 = 1;
        const ACTION_ALLOW: u32 = 2;
        let action_value = if action_str == "deny" {
            ACTION_DENY
        } else {
            ACTION_ALLOW
        };

        // d. Insertion dans la Map BPF
        match self.blocklist.lock().await.insert(key, action_value, 0) {
            Ok(_) => info!("🔥 Règle ajoutée au noyau (Hot-Reload)"),
            Err(e) => {
                log::error!("CRITIQUE: Règle ajoutée en DB mais échec BPF: {}", e);
            }
        }

        info!(
            "✅ Règle créée [ID: {} | Nom: {}] : {} -> {} | Port Dest: {} | Proto: {} | Action: {}",
            created_rule_id,
            rule_to_create.name,
            rule_to_create.source_ip,
            rule_to_create.dest_ip,
            dest_port_db.map_or("*".to_string(), |p| p.to_string()),
            rule_to_create.protocol,
            action_str
        );

        Ok(Response::new(CreateRuleResponse {
            created_rule_id,
            message: format!("Règle créée avec succès avec l'ID {}.", created_rule_id),
        }))
    }

    async fn delete_rule(
        &self,
        request: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let rule_id_to_delete = req_data
            .rule
            .map(|r| r.id)
            .ok_or_else(|| tonic::Status::invalid_argument("Données de suppression manquantes"))?;

        // Récupération détails pour supprimer de BPF
        let row_opt = self.db_client.query_opt("SELECT source_ip, dest_ip, dest_port, protocol FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
            .map_err(|e| tonic::Status::internal(format!("Erreur récupération règle: {}", e)))?;

        let row = row_opt.ok_or_else(|| {
            tonic::Status::not_found(format!("Règle ID {} non trouvée", rule_id_to_delete))
        })?;

        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let dest_port: Option<i32> = row.get("dest_port");
        let protocol: Option<String> = row.get("protocol");

        // --- 2. Suppression de la Map BPF ---
        let ip_src = if source_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
        };
        let ip_dst = if dest_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
        };

        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (dest_port.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&protocol),
            _pad: 0,
        };

        {
            let mut map = self.blocklist.lock().await;
            if map.remove(&key).is_ok() {
                info!("🔥 Règle supprimée du noyau (Hot-Reload): {:?}", key);
            } else {
                warn!(
                    "⚠️ Tentative de suppression BPF échouée (clé non trouvée ?): {:?}",
                    key
                );
            }
        }
        // Suppression DB
        self.db_client
            .execute("DELETE FROM rules WHERE id = $1", &[&rule_id_to_delete])
            .await
            .map_err(|e| tonic::Status::internal(format!("Erreur suppression DB: {}", e)))?;

        // --- AJOUT LOG SUPPRESSION GLOBALE ---
        info!(
            "🗑️  Règle supprimée [ID: {}] : {} -> {}",
            rule_id_to_delete, source_ip, dest_ip
        );

        Ok(Response::new(DeleteRuleResponse {
            delete_rule_id: rule_id_to_delete,
            message: format!("Règle ID {} supprimée avec succès.", rule_id_to_delete),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    validate_args(&opt);

    Logger::try_with_str("info")?
        .log_to_file(
            FileSpec::default()
                .directory("logs")
                .basename("firewall")
                .suppress_timestamp(),
        )
        .append()
        .duplicate_to_stdout(Duplicate::Info)
        .start()
        .context("Erreur initialisation logger")?;
    info!("Logger initialisé.");

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;
    let _ = EbpfLogger::init(&mut bpf);

    let program: &mut Xdp = bpf
        .program_mut("xdp_firewall")
        .ok_or_else(|| anyhow::anyhow!("Programme eBPF 'xdp_firewall' introuvable"))?
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    info!("eBPF program loaded and attached to {}.", opt.iface);

    // Récupération de la map
    let map = bpf
        .take_map("BLOCKLIST")
        .ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST introuvable"))?;

    let blocklist_map: HashMap<aya::maps::MapData, IpPort, u32> = HashMap::try_from(map)?;

    let blocklist: Arc<tokio::sync::Mutex<HashMap<aya::maps::MapData, IpPort, u32>>> =
        Arc::new(tokio::sync::Mutex::new(blocklist_map));

    let (pg_client_raw, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall",
        tokio_postgres::NoTls,
    )
    .await?;
    let pg_client = Arc::new(pg_client_raw);
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // Initial load des règles dans BPF
    // J'ai ajouté 'name' dans le SELECT ici aussi pour l'avoir dans les logs
    let initial_rules = pg_client
        .query(
            "SELECT id, name, source_ip, dest_ip, dest_port, action, protocol FROM rules",
            &[],
        )
        .await?;
    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2;

    info!("--- Chargement des règles au démarrage ---");

    for row in initial_rules {
        let id: i32 = row.get("id");
        let name: String = row.get("name"); // Récupération du nom
        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let dest_port: Option<i32> = row.get("dest_port");
        let action: String = row.get("action");
        let protocol: Option<String> = row.get("protocol");

        let ip_src = if source_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            source_ip.parse()?
        };
        let ip_dst = if dest_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            dest_ip.parse()?
        };

        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (dest_port.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&protocol),
            _pad: 0,
        };
        let action_value = match action.to_lowercase().as_str() {
            "deny" => ACTION_DENY,
            "allow" => ACTION_ALLOW,
            _ => continue,
        };

        blocklist.lock().await.insert(key, action_value, 0)?;

        // --- AJOUT LOG DEMARRAGE AVEC LE NOM ---
        info!(
            "📜 Règle chargée [ID: {} | {}] : {} -> {} | Port Dest: {} | Proto: {} | Action: {}",
            id,
            name,
            source_ip,
            dest_ip,
            dest_port.map_or("*".to_string(), |p| p.to_string()),
            protocol.unwrap_or_else(|| "any".to_string()),
            action
        );
    }
    info!("--- Fin du chargement des règles ---");

    let firewall_service = MyFirewallService {
        db_client: Arc::clone(&pg_client),
        blocklist: Arc::clone(&blocklist),
    };
    let grpc_addr = "[::1]:50051".parse()?;
    tokio::spawn(
        Server::builder()
            .add_service(FirewallServiceServer::new(firewall_service))
            .serve(grpc_addr),
    );

    info!("Firewall en marche. Ctrl-C pour arrêter.");
    signal::ctrl_c().await?;
    info!("Arrêt du firewall...");
    Ok(())
}