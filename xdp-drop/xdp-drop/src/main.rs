use anyhow::Context;
use aya::{
    Ebpf,
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::{Parser, CommandFactory};
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn};
use std::sync::Arc; 
use std::net::Ipv4Addr;
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
use crate::firewall::{FirewallStatus, RuleInfo, RuleListResponse, CreateRuleRequest, CreateRuleResponse, DeleteRuleRequest, DeleteRuleResponse};
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
            "SELECT id, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules",
            &[],
        )
        .await
        .context("Erreur lors de l'exécution du SELECT sur rules")?;

    let mut rule_infos = Vec::new();
    for row in rows {
        let id: i32 = row.get("id");
        let source_ip_str: String = row.get("source_ip");
        let dest_ip_str: String = row.get("dest_ip");
        let source_port_opt: Option<i32> = row.get("source_port");
        let dest_port_opt: Option<i32> = row.get("dest_port");
        let action_str: String = row.get("action");
        let protocol_opt: Option<String> = row.get("protocol");
        let usage_count_val: i32 = row.get("usage_count");

        rule_infos.push(RuleInfo {
            id,
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
        Ok(Response::new(FirewallStatus { status: "UP".to_string() }))
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
                Err(tonic::Status::internal(format!("Échec de la récupération des règles: {}", e)))
            }
        }
    }
    
    async fn create_rule(
        &self,
        request: Request<CreateRuleRequest>,
    ) -> Result<Response<CreateRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let rule_to_create = req_data.rule.ok_or_else(|| tonic::Status::invalid_argument("Données de règle manquantes"))?;
        if rule_to_create.source_ip.is_empty() || rule_to_create.dest_ip.is_empty() {
            return Err(tonic::Status::invalid_argument("Les adresses IP source et destination ne peuvent pas être vides."));
        }
        let action_str = rule_to_create.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(tonic::Status::invalid_argument("Action invalide. Doit être 'allow' ou 'deny'."));
        }
        let source_port_db: Option<i32> = rule_to_create.source_port.parse().ok();
        let dest_port_db: Option<i32> = rule_to_create.dest_port.parse().ok();

        // Insertion DB
        let created_rule_id: i32 = self.db_client.query_one(
            "INSERT INTO rules (source_ip, dest_ip, source_port, dest_port, action, protocol) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[&rule_to_create.source_ip, &rule_to_create.dest_ip, &source_port_db, &dest_port_db, &action_str, &rule_to_create.protocol.to_uppercase()],
        ).await.map_err(|e| {
            log::error!("Erreur insertion DB: {}", e);
            tonic::Status::internal(format!("Échec création règle DB: {}", e))
        })?.get(0);

        // --- AJOUT LOG CREATION ---
        info!(
            "✅ Règle créée [ID: {}] : {} -> {} | Port Dest: {} | Proto: {} | Action: {}",
            created_rule_id,
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
        let rule_id_to_delete = req_data.rule.map(|r| r.id).ok_or_else(|| tonic::Status::invalid_argument("Données de suppression manquantes"))?;
        
        // Récupération détails pour supprimer de BPF
        let row_opt = self.db_client.query_opt("SELECT source_ip, dest_ip, dest_port FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
            .map_err(|e| tonic::Status::internal(format!("Erreur récupération règle: {}", e)))?;
        let row = row_opt.ok_or_else(|| tonic::Status::not_found(format!("Règle ID {} non trouvée", rule_id_to_delete)))?;
        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let dest_port: Option<i32> = row.get("dest_port");

        if let (Ok(ip_src), Ok(ip_dst)) = (source_ip.parse::<Ipv4Addr>(), dest_ip.parse::<Ipv4Addr>()) {
            let key = IpPort {
                addr: u32::from(ip_src).to_be(),
                addr_dest: u32::from(ip_dst).to_be(),
                port: (dest_port.unwrap_or(0) as u16).to_be(),
                protocol: PROTO_ANY,
                _pad: 0,
            };
            let mut map = self.blocklist.lock().await;
            if map.remove(&key).is_ok() {
                // --- AJOUT LOG SUPPRESSION BPF ---
                // (Log technique BPF déjà présent, optionnel si vous voulez le garder)
                // info!("Règle supprimée à chaud du BPF: {:?}", key);
            }
        }

        // Suppression DB
        self.db_client.execute("DELETE FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
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
        .log_to_file(FileSpec::default().directory("logs").basename("firewall").suppress_timestamp())
        .append()
        .duplicate_to_stdout(Duplicate::Info)
        .start()
        .context("Erreur initialisation logger")?;
    info!("Logger initialisé.");

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-drop")))?;
    let _ = EbpfLogger::init(&mut bpf);

    let program: &mut Xdp = bpf.program_mut("xdp_firewall")
        .ok_or_else(|| anyhow::anyhow!("Programme eBPF 'xdp_firewall' introuvable"))?
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    info!("eBPF program loaded and attached to {}.", opt.iface);

    // Récupération de la map en prenant la possession (ownership) pour éviter les erreurs de type/lifetime
    let map = bpf.take_map("BLOCKLIST")
        .ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST introuvable"))?;
    
    let blocklist_map: HashMap<aya::maps::MapData, IpPort, u32> = HashMap::try_from(map)?;

    let blocklist: Arc<tokio::sync::Mutex<HashMap<aya::maps::MapData, IpPort, u32>>> =
        Arc::new(tokio::sync::Mutex::new(blocklist_map));

    let (pg_client_raw, connection) = tokio_postgres::connect("host=localhost user=postgres password=postgres dbname=firewall", tokio_postgres::NoTls).await?;
    let pg_client = Arc::new(pg_client_raw);
    tokio::spawn(async move { let _ = connection.await; });

    // Initial load des règles dans BPF
    let initial_rules = pg_client.query("SELECT id, source_ip, dest_ip, dest_port, action, protocol FROM rules", &[]).await?;
    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2;
    
    info!("--- Chargement des règles au démarrage ---");
    
    for row in initial_rules {
        let id: i32 = row.get("id");
        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let dest_port: Option<i32> = row.get("dest_port");
        let action: String = row.get("action");
        let protocol: Option<String> = row.get("protocol");

        let ip_src = if source_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { source_ip.parse()? };
        let ip_dst = if dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { dest_ip.parse()? };

        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (dest_port.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&protocol),
            _pad: 0,
        };
        let action_value = match action.to_lowercase().as_str() { "deny" => ACTION_DENY, "allow" => ACTION_ALLOW, _ => continue };
        
        blocklist.lock().await.insert(key, action_value, 0)?;

        // --- AJOUT LOG DEMARRAGE ---
        info!(
            "📜 Règle chargée [ID: {}] : {} -> {} | Port Dest: {} | Proto: {} | Action: {}", 
            id, 
            source_ip, 
            dest_ip, 
            dest_port.map_or("*".to_string(), |p| p.to_string()),
            protocol.unwrap_or_else(|| "any".to_string()),
            action
        );
    }
    info!("--- Fin du chargement des règles ---");

    let firewall_service = MyFirewallService { db_client: Arc::clone(&pg_client), blocklist: Arc::clone(&blocklist) };
    let grpc_addr = "[::1]:50051".parse()?;
    tokio::spawn(Server::builder().add_service(FirewallServiceServer::new(firewall_service)).serve(grpc_addr));

    info!("Firewall en marche. Ctrl-C pour arrêter.");
    signal::ctrl_c().await?;
    info!("Arrêt du firewall...");
    Ok(())
}