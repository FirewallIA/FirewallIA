use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use flexi_logger::{Logger, FileSpec, Duplicate};
use log::{info, warn};
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use firewall::firewall_service_server::{FirewallService, FirewallServiceServer};
use firewall::{Empty, FirewallStatus};
use xdp_drop_common::IpPort;

pub mod firewall {
    include!(concat!(env!("src"), "/firewall.rs"));
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s8")]
    iface: String,
}

#[derive(Default)]
pub struct MyFirewallService;

#[tonic::async_trait]
impl FirewallService for MyFirewallService {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<FirewallStatus>, Status> {
        // Logique pour déterminer si le firewall est UP ou DOWN
        let status = FirewallStatus {
            status: "UP".to_string(), // Exemple, tu pourrais changer selon la logique de ton firewall
        };
        Ok(Response::new(status))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // 📝 Initialisation du logger : log dans fichier + stdout
    Logger::try_with_str("info")?
        .log_to_file(
            FileSpec::default()
                .directory("logs")     // dossier où sera créé le log
                .basename("firewall")  // nom du fichier log : firewall.log
                .suppress_timestamp(), // pas de timestamp dans le nom de fichier
        )
        .append()
        .duplicate_to_stdout(Duplicate::Info) // affiche aussi dans le terminal
        .start()
        .context("Erreur lors de l'initialisation du logger")?;

    // 🧠 Chargement du programme eBPF
    let mut bpf = aya::Bpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-drop"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Logger eBPF non initialisé : {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("Échec de l'attachement du programme XDP")?;

    // 🔒 Ajout d'une IP + port à bloquer
    let mut blocklist: HashMap<_, IpPort, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    // 🐘 Connexion à la base PostgreSQL
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall",
        tokio_postgres::NoTls,
    )
    .await
    .context("Erreur de connexion à PostgreSQL")?;

    // 🧵 Exécuter la connexion en tâche asynchrone
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Erreur de connexion PostgreSQL : {}", e);
        }
    });

    // 🗂️ Sélection des règles depuis la table
    let rows = client
        .query(
            "SELECT id, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules",
            &[],
        )
        .await
        .context("Échec de la requête SELECT")?;

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

        let ip = source_ip.parse::<std::net::Ipv4Addr>()?;
        let ip_dest = dest_ip.parse::<std::net::Ipv4Addr>()?;
        let port = dest_port.unwrap_or(0) as u16;
        info!("INFO IP : {} {}", ip, port);

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
                warn!("Action inconnue '{}' pour la règle #{}, ignorée.", action, id);
                continue;
            }
        };

        blocklist.insert(key, action_value, 0)?;

        info!(
            "🛡️ Règle #{}: {}:{} → {}:{} | Action: {} | Proto: {} | Utilisations: {}",
            id,
            source_ip,
            source_port.map_or("*".to_string(), |p| p.to_string()),
            dest_ip,
            dest_port.map_or("*".to_string(), |p| p.to_string()),
            action,
            protocol.unwrap_or_else(|| "any".into()),
            usage_count
        );
    }

    // Démarrage du serveur gRPC pour exposer le statut du firewall
    let grpc_addr = "[::1]:50051".parse()?;
    let firewall_service = MyFirewallService::default();
    tokio::spawn(async move {
        Server::builder()
            .add_service(FirewallServiceServer::new(firewall_service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    // ✅ Logs de statut
    info!("🔥 Le firewall est en marche !");
    info!("⏳ Appuyez sur Ctrl-C pour arrêter...");

    signal::ctrl_c().await?;
    info!("🛑 Arrêt du firewall...");

    Ok(())
}
