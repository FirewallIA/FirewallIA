use anyhow::Context;
use aya::{
    Bpf,
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn};
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use xdp_drop_common::IpPort;
// Import du proto compilé gRPC
// Ceci va créer les modules `firewall` et `google` (avec `protobuf` dedans)
// à la racine de votre crate (ou du module courant si utilisé dans un sous-module).
pub mod firewall {
tonic::include_proto!("firewall");
}
pub mod google {
    pub mod protobuf { // Crée la hiérarchie google::protobuf
        tonic::include_proto!("google.protobuf"); // Inclut OUT_DIR/google.protobuf.rs
    }
}

use crate::firewall::firewall_service_server::{FirewallService, FirewallServiceServer};
use crate::firewall::{FirewallStatus, RuleInfo, RuleListResponse};
use crate::google::protobuf::Empty;



#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

pub struct MyFirewallService {
    db_client: tokio_postgres::Client,
}


// Fonction pour récupérer et formater les règles (sera appelée par main et ListRules)
async fn fetch_and_format_rules_from_db(
    db_client: &tokio_postgres::Client,
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
        _request: Request<crate::google::protobuf::Empty>, // Doit utiliser le Empty importé
    ) -> Result<Response<firewall::FirewallStatus>, Status> { // firewall::FirewallStatus est correct
        let status = firewall::FirewallStatus {
            status: "UP".to_string(),
        };
        Ok(Response::new(status))
    }

    async fn list_rules(
        &self,
        _request: Request<crate::google::protobuf::Empty>,
    ) -> Result<Response<RuleListResponse>, tonic::Status> {
        info!("gRPC: Appel de ListRules reçu");
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
}

  


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

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

    // Chargement du programme eBPF
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Logger eBPF non initialisé : {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall")
        .context("Programme xdp_firewall introuvable")?
        .try_into()
        .context("Erreur de conversion du programme en Xdp")?;
    program.load().context("Erreur de chargement du programme XDP")?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("Erreur d'attachement du programme XDP")?;

    // Blocage d'IP
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST")
        .context("Map BLOCKLIST introuvable dans eBPF")?)?;

    // Connexion PostgreSQL
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall",
        tokio_postgres::NoTls,
    )
    .await
    .context("Erreur de connexion à PostgreSQL")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Erreur de connexion PostgreSQL : {e}");
        }
    });

    // Lecture des règles
    let rows = client
        .query(
            "SELECT id, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules",
            &[],
        )
        .await
        .context("Erreur lors de l'exécution du SELECT sur rules")?;

    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2;

    info!("📋 Règles trouvées dans la base :");
    for row in rows {
        let id: i32 = row.get("id");
        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let source_port: Option<i32> = row.get("source_port");
        let dest_port: Option<i32> = row.get("dest_port");
        let action: String = row.get("action");
        let protocol: Option<String> = row.get("protocol");
        let usage_count: i32 = row.get("usage_count");

        let ip = source_ip.parse::<std::net::Ipv4Addr>()
            .context(format!("IP source invalide pour la règle {id}"))?;
        let ip_dest = dest_ip.parse::<std::net::Ipv4Addr>()
            .context(format!("IP destination invalide pour la règle {id}"))?;
        let port = dest_port.unwrap_or(0) as u16;

        let key = IpPort {
            addr: u32::from(ip).to_be(),
            addr_dest: u32::from(ip_dest).to_be(),
            port,
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
            .context(format!("Erreur lors de l'insertion de la règle #{id}"))?;

        info!(
            "🛡️ Règle #{id}: {source_ip}:{} → {dest_ip}:{} | Action: {action} | Proto: {} | Utilisations: {usage_count}",
            source_port.map_or("*".to_string(), |p| p.to_string()),
            dest_port.map_or("*".to_string(), |p| p.to_string()),
            protocol.unwrap_or_else(|| "any".to_string()),
        );
    }

    // Serveur gRPC
    let grpc_addr = "[::1]:50051".parse()
        .context("Adresse gRPC invalide")?;
    let firewall_service = MyFirewallService::default();
    let grpc_server = Server::builder()
        .add_service(FirewallServiceServer::new(firewall_service))
        .serve(grpc_addr);

    tokio::spawn(async move {
        if let Err(e) = grpc_server.await {
            eprintln!("Erreur serveur gRPC : {e}");
        }
    });

    info!("🔥 Le firewall est en marche !");
    info!("⏳ Appuyez sur Ctrl-C pour arrêter...");

    signal::ctrl_c().await.context("Erreur lors de l'attente du signal Ctrl-C")?;
    info!("🛑 Arrêt du firewall...");

    Ok(())
}
