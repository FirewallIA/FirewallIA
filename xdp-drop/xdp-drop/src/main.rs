use anyhow::Context;
use aya::{
    Bpf,
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::{Parser, CommandFactory};
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn};
use std::sync::Arc; 
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use xdp_drop_common::IpPort;

// ... (modules firewall et google) ...
pub mod firewall {
tonic::include_proto!("firewall");
}
pub mod google {
    pub mod protobuf { 
        tonic::include_proto!("google.protobuf"); 
    }
}

use crate::firewall::firewall_service_server::{FirewallService, FirewallServiceServer};
use crate::firewall::{FirewallStatus, RuleInfo, RuleListResponse, CreateRuleRequest, CreateRuleResponse, RuleData, DeleteRuleRequest, DeleteRuleResponse, RuleDataDelete};
use crate::google::protobuf::Empty;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'i', long = "int")]
    iface: String,
}

fn validate_args(opt: &Opt) {
    if opt.iface.trim().is_empty() {
        let mut cmd = Opt::command();
        eprintln!("Erreur : l'interface réseau est requise.\n");
        cmd.print_help().unwrap();
        std::process::exit(1);
    }
}

//  RUST_LOG=info cargo run -- -i enp0s1
pub struct MyFirewallService {
    db_client: Arc<tokio_postgres::Client>,
}

// Fonction pour récupérer et formater les règles
async fn fetch_and_format_rules_from_db(
    db_client: &Arc<tokio_postgres::Client>,
) -> Result<Vec<RuleInfo>, anyhow::Error> {
    // db_client est déjà une référence à un Arc, donc on peut l'utiliser directement
    // ou le déréférencer une fois: let client_ref = &**db_client;
    let rows = db_client // Utilisation directe de la référence à l'Arc, qui déréférence vers Client
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
        let status = FirewallStatus {
            status: "UP".to_string(),
        };
        Ok(Response::new(status))
    }

    async fn list_rules(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RuleListResponse>, tonic::Status> {
        info!("gRPC: Appel de ListRules reçu");
        // self.db_client est un Arc<Client>, on passe une référence à cet Arc
        match fetch_and_format_rules_from_db(&self.db_client).await {
            Ok(rules) => {
                let response = RuleListResponse { rules };
                Ok(Response::new(response))
            }
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
        info!("gRPC: Appel de CreateRule reçu pour : {:?}", req_data.rule);

        // 1. Validation (exemple simple, à étoffer)
        let rule_to_create = match req_data.rule {
            Some(r) => r,
            None => {
                return Err(tonic::Status::invalid_argument("Données de règle manquantes dans la requête"));
            }
        };

        if rule_to_create.source_ip.is_empty() || rule_to_create.dest_ip.is_empty() {
            return Err(tonic::Status::invalid_argument("Les adresses IP source et destination ne peuvent pas être vides."));
        }
        // Ajoutez d'autres validations : format IP, format port, valeurs d'action/protocole valides, etc.
        // Exemple de validation d'action
        let action_str = rule_to_create.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(tonic::Status::invalid_argument(
                "Action invalide. Doit être 'allow' ou 'deny'.",
            ));
        }
        
        // Convertir les ports string en Option<i32> pour la DB, ou gérer le "*"
        let source_port_db: Option<i32> = rule_to_create.source_port.parse().ok();
        let dest_port_db: Option<i32> = rule_to_create.dest_port.parse().ok();


        // 2. Insertion dans la base de données PostgreSQL
        // La colonne 'id' est SERIAL, donc elle sera auto-générée. 'usage_count' aura sa valeur par défaut (0).
        let created_rule_id: i32;
        match self.db_client.query_one(
            "INSERT INTO rules (source_ip, dest_ip, source_port, dest_port, action, protocol) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[
                &rule_to_create.source_ip,
                &rule_to_create.dest_ip,
                &source_port_db,    // Utiliser les Option<i32>
                &dest_port_db,      // Utiliser les Option<i32>
                &action_str,        // Utiliser la version validée/normalisée
                &rule_to_create.protocol.to_uppercase(),
            ],
        ).await {
            Ok(row) => {
                created_rule_id = row.get(0);
                info!("Règle insérée dans la DB avec l'ID: {}", created_rule_id);
            }
            Err(e) => {
                log::error!("Erreur lors de l'insertion de la règle dans la DB: {}", e);
                return Err(tonic::Status::internal(format!(
                    "Échec de la création de la règle en base de données: {}", e
                )));
            }
        }

        // 3. (Optionnel mais important) Insertion dans la map eBPF `BLOCKLIST`
        // Vous aurez besoin d'un accès mutable à la map BPF.
        // Cela complique un peu les choses car MyFirewallService ne l'a pas actuellement.
        // Solutions possibles :
        //    a) Passer un `Arc<Mutex<HashMap<_, IpPort, u32>>>` à MyFirewallService (si HashMap est celle d'Aya).
        //    b) Utiliser un canal (mpsc) pour envoyer une commande de mise à jour à la tâche principale qui gère BPF.
        //    c) Recharger toutes les règles depuis la DB vers BPF (moins efficace pour une seule règle).
        //
        // Pour l'instant, je vais omettre cette partie pour garder l'exemple focalisé sur gRPC et DB.
        // MAIS C'EST UNE ÉTAPE CRUCIALE pour que la règle soit active dans le firewall.
        // Vous devrez trouver un moyen de mettre à jour la map `blocklist` partagée.

        // Exemple de logique pour BPF (si vous aviez accès à `blocklist`):
        /*
        match (rule_to_create.source_ip.parse::<std::net::Ipv4Addr>(), rule_to_create.dest_ip.parse::<std::net::Ipv4Addr>()) {
            (Ok(ip_src), Ok(ip_dst)) => {
                let port_for_bpf = if rule_to_create.dest_port == "*" { 0 } else { rule_to_create.dest_port.parse().unwrap_or(0) };
                let key = IpPort {
                    addr: u32::from(ip_src).to_be(),
                    addr_dest: u32::from(ip_dst).to_be(),
                    port: port_for_bpf,
                    _pad: 0,
                };
                const ACTION_DENY_U32: u32 = 1; // Assurez-vous que ces constantes sont accessibles
                const ACTION_ALLOW_U32: u32 = 2;
                let action_value_bpf = if action_str == "deny" { ACTION_DENY_U32 } else { ACTION_ALLOW_U32 };

                // ICI, il faudrait un accès à la map BPF
                // blocklist_map_ref.insert(key, action_value_bpf, 0).map_err(|e| ...)?;
                info!("Règle (potentiellement) insérée/mise à jour dans la map BPF.");
            }
            _ => {
                warn!("IP invalide pour l'insertion BPF, règle ID {}: {} -> {}", created_rule_id, rule_to_create.source_ip, rule_to_create.dest_ip);
            }
        }
        */


        // 4. Retourner la réponse
        let response = CreateRuleResponse {
            created_rule_id,
            message: format!("Règle créée avec succès avec l'ID {}.", created_rule_id),
        };
        Ok(Response::new(response))
    }
    async fn delete_rule(
        &self,
        request: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, tonic::Status> {
 let req_data = request.into_inner();
        let rule_id_to_delete = match req_data.rule {
            Some(r) => r.id,
            None => {
                return Err(tonic::Status::invalid_argument("Données de suppression de règle manquantes."));
            }
        };
        info!("gRPC: Appel de DeleteRule reçu pour l'ID: {}", rule_id_to_delete);

        // 1. Récupérer les infos de la règle depuis la DB pour la clé BPF
        let rule_details = match self.db_client.query_opt(
            "SELECT source_ip, dest_ip, dest_port FROM rules WHERE id = $1",
            &[&rule_id_to_delete]
        ).await {
            Ok(Some(row)) => {
                let source_ip: String = row.get(0);
                let dest_ip: String = row.get(1);
                let dest_port: Option<i32> = row.get(2); // dest_port de la DB
                (source_ip, dest_ip, dest_port)
            }
            Ok(None) => {
                warn!("Tentative de suppression de la règle ID {}, mais elle n'existe pas dans la DB.", rule_id_to_delete);
                return Err(tonic::Status::not_found(format!(
                    "Règle avec ID {} non trouvée.", rule_id_to_delete
                )));
            }
            Err(e) => {
                log::error!("Erreur lors de la récupération des détails de la règle ID {}: {}", rule_id_to_delete, e);
                return Err(tonic::Status::internal(format!(
                    "Échec de la récupération des détails de la règle: {}", e
                )));
            }
        };

        // 2. Tentative de suppression de la map eBPF

        // 3. Suppression de la base de données PostgreSQL
        match self.db_client.execute(
            "DELETE FROM rules WHERE id = $1",
            &[&rule_id_to_delete]
        ).await {
            Ok(rows_affected) => {
                if rows_affected == 0 {
                    // Cela ne devrait pas arriver si on l'a trouvée à l'étape 1, mais par sécurité
                    warn!("Tentative de suppression de la règle ID {} (DB), mais 0 lignes affectées (déjà supprimée?).", rule_id_to_delete);
                    return Err(tonic::Status::not_found(format!(
                        "Règle avec ID {} non trouvée lors de la suppression finale (ou déjà supprimée).", rule_id_to_delete
                    )));
                }
                info!("Règle ID {} supprimée de la DB ({} lignes affectées).", rule_id_to_delete, rows_affected);
            }
            Err(e) => {
                log::error!("Erreur lors de la suppression de la règle ID {} de la DB: {}", rule_id_to_delete, e);
                return Err(tonic::Status::internal(format!(
                    "Échec de la suppression de la règle en base de données: {}", e
                )));
            }
        }

        // 4. Retourner la réponse
        let response = DeleteRuleResponse {
            delete_rule_id: rule_id_to_delete, // Le proto demande delete_rule_id, pas deleted_rule_id
            message: format!("Règle ID {} supprimée avec succès.", rule_id_to_delete),
        };
        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    validate_args(&opt);

    // Logger
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
    .context("Erreur lors de l'initialisation du logger")?;
    info!("Logger initialisé.");

    // Chargement du programme eBPF
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))
    .context("Failed to load BPF program")?; // Ok, Bpf::load retourne Result

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("eBPF logger not initialized: {}", e); // Ok, c'est un Result
    }

    let program: &mut Xdp = bpf
        .program_mut("xdp_firewall") // Ceci retourne Option<&mut Program>
        .ok_or_else(|| anyhow::anyhow!("Programme eBPF 'xdp_firewall' introuvable dans BPF"))? // Convertit Option en Result
        .try_into() // try_into sur Program retourne Result<&mut Xdp, _>
        .context("Erreur de conversion du programme en Xdp")?;
    
    program.load().context("Erreur de chargement du programme XDP")?; // load retourne Result
    program
        .attach(&opt.iface, XdpFlags::default()) // attach retourne Result
        .context(format!("Erreur d'attachement du programme XDP à l'interface {}", opt.iface))?;
    
    info!("eBPF program loaded and attached to {}.", opt.iface);


    // Blocage d'IP
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST")
        .context("Map BLOCKLIST introuvable dans eBPF")?)?;


    // Connexion PostgreSQL
    let (pg_client_raw, connection) = tokio_postgres::connect( // Renommé pour clarté
        "host=localhost user=postgres password=postgres dbname=firewall",
        tokio_postgres::NoTls,
    )
    .await
    .context("Erreur de connexion à PostgreSQL")?;
    info!("Connecté à PostgreSQL.");

    // Envelopper le client dans un Arc pour le partage
    let pg_client = Arc::new(pg_client_raw); 

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Erreur de connexion PostgreSQL en tâche de fond : {e}");
        }
    });

    // Lecture des règles pour le chargement initial dans eBPF et l'affichage
    info!("📋 Chargement des règles initiales depuis la base de données...");
    // Utiliser une référence à l'Arc ici aussi, ou directement pg_client.
    // Les méthodes de tokio_postgres::Client sont accessibles via &Arc<Client> grâce à la déréférencement automatique (Deref).
    let initial_rules_from_db = pg_client 
        .query(
            "SELECT id, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules",
            &[],
        )
        .await
        .context("Erreur lors de l'exécution du SELECT sur rules pour chargement initial")?;

    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2;

    info!("📋 Règles trouvées dans la base (pour chargement BPF et log initial) :");
    for row in initial_rules_from_db {
        let id: i32 = row.get("id");
        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let source_port: Option<i32> = row.get("source_port");
        let dest_port: Option<i32> = row.get("dest_port");
        let action: String = row.get("action");
        let protocol: Option<String> = row.get("protocol");
        let usage_count: i32 = row.get("usage_count");

        let ip_addr = source_ip.parse::<std::net::Ipv4Addr>()
            .context(format!("IP source invalide pour la règle {id}"))?;
        let ip_dest_addr = dest_ip.parse::<std::net::Ipv4Addr>()
            .context(format!("IP destination invalide pour la règle {id}"))?;
        let port_val = dest_port.unwrap_or(0) as u16;

        let key = IpPort {
            addr: u32::from(ip_addr).to_be(),
            addr_dest: u32::from(ip_dest_addr).to_be(),
            port: port_val,
            _pad: 0,
        };

        let action_value = match action.to_lowercase().as_str() {
            "deny" => ACTION_DENY,
            "allow" => ACTION_ALLOW,
            _ => {
                warn!("Action inconnue '{}' pour la règle #{id}, ignorée.", action);
                continue;
            }
        };

        blocklist.insert(key, action_value, 0)
            .context(format!("Erreur lors de l'insertion de la règle #{id} dans BPF"))?;

        info!(
            "🛡️ Règle #{id}: {source_ip}:{} → {dest_ip}:{} | Action: {action} | Proto: {} | Utilisations: {usage_count}",
            source_port.map_or("*".to_string(), |p| p.to_string()),
            dest_port.map_or("*".to_string(), |p| p.to_string()),
            protocol.unwrap_or_else(|| "any".to_string()),
        );
    }
    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags")?;


    // Serveur gRPC
    let grpc_addr = "[::1]:50051".parse().context("Adresse gRPC invalide")?;

    let firewall_service = MyFirewallService {
        db_client: Arc::clone(&pg_client) // <--- MODIFICATION ICI: cloner l'Arc
    };
    info!("Service Firewall gRPC en cours de création...");

    let grpc_server_future = Server::builder()
        .add_service(FirewallServiceServer::new(firewall_service))
        .serve(grpc_addr);

    tokio::spawn(async move {
        info!("Serveur gRPC démarré sur {}", grpc_addr);
        if let Err(e) = grpc_server_future.await {
            eprintln!("Erreur serveur gRPC : {e}");
        }
    });

    info!("🔥 Le firewall est en marche !");
    info!("⏳ Appuyez sur Ctrl-C pour arrêter...");

    signal::ctrl_c().await.context("Erreur lors de l'attente du signal Ctrl-C")?;
    info!("🛑 Arrêt du firewall...");

    Ok(())
}