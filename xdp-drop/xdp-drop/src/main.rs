use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    maps::PerCpuArray,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::{CommandFactory, Parser};
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn, error};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tonic::{transport::Server, Request, Response};
use xdp_drop_common::{IpPort, PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use xdp_drop_common::{STAT_INBOUND, STAT_OUTBOUND, STAT_BLOCKED};
use std::time::SystemTime;

use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use crate::firewall::LogEntry;

use aya::maps::perf::AsyncPerfEventArray;
use xdp_drop_common::PacketLog;
use aya::util::online_cpus;
use bytes::BytesMut;

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
    RuleInfo, RuleListResponse, GetTrafficStatsRequest, GetTrafficStatsResponse, 
    UpdateRuleRequest, UpdateRuleResponse 
};
use crate::google::protobuf::Empty;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'i', long = "int")]
    iface: String,
}

#[derive(Debug)]
struct DbLogMessage {
    timestamp: SystemTime,
    src_ip: String,
    dest_ip: String,
    src_port: i32,
    dest_port: i32,
    protocol: String,
    action: String,
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

// Utilitaire pour récupérer le nom du protocole (u32 -> String)
fn get_proto_name(proto: u32) -> String {
    match proto {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        _ => format!("{}", proto),
    }
}

fn get_interfaces(target: &str) -> Vec<String> {
    let target = target.trim();
    
    // Si l'utilisateur a tapé "*" ou "all"
    if target == "*" || target.to_lowercase() == "all" {
        let mut ifaces = Vec::new();
        // On lit le dossier système Linux qui contient les interfaces réseau
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    // On ignore généralement 'lo' (loopback) pour un firewall
                    if name != "lo" {
                        ifaces.push(name);
                    }
                }
            }
        }
        return ifaces;
    }
    
    // Sinon, on sépare par des virgules
    target.split(',')
          .map(|s| s.trim().to_string())
          .filter(|s| !s.is_empty())
          .collect()
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
    blocklist: Arc<tokio::sync::Mutex<HashMap<aya::maps::MapData, IpPort, u32>>>,
    log_tx: broadcast::Sender<LogEntry>,
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
        rule_infos.push(RuleInfo {
            id: row.get("id"),
            name: row.get("name"),
            source_ip: row.get("source_ip"),
            dest_ip: row.get("dest_ip"),
            source_port: row.get::<_, Option<i32>>("source_port").map_or("*".to_string(), |p| p.to_string()),
            dest_port: row.get::<_, Option<i32>>("dest_port").map_or("*".to_string(), |p| p.to_string()),
            action: row.get("action"),
            protocol: row.get::<_, Option<String>>("protocol").unwrap_or_else(|| "any".to_string()),
            usage_count: row.get("usage_count"),
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

    type WatchLogsStream = ReceiverStream<Result<LogEntry, tonic::Status>>;

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

        if rule_to_create.source_ip.is_empty() || rule_to_create.dest_ip.is_empty() {
            return Err(tonic::Status::invalid_argument("Les adresses IP sont requises."));
        }
        let action_str = rule_to_create.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(tonic::Status::invalid_argument("Action invalide."));
        }

        let source_port_db: Option<i32> = rule_to_create.source_port.parse().ok();
        let dest_port_db: Option<i32> = rule_to_create.dest_port.parse().ok();
        let dest_port_u16 = dest_port_db.unwrap_or(0) as u16;

        let created_rule_id: i32 = self.db_client.query_one(
            "INSERT INTO rules (name, source_ip, dest_ip, source_port, dest_port, action, protocol) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            &[
                &rule_to_create.name, &rule_to_create.source_ip, &rule_to_create.dest_ip,
                &source_port_db, &dest_port_db, &action_str, &rule_to_create.protocol.to_uppercase()
            ],
        ).await.map_err(|e| {
            log::error!("Erreur insertion DB: {}", e);
            tonic::Status::internal(format!("Échec création règle DB: {}", e))
        })?.get(0);

        let ip_src = if rule_to_create.source_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { rule_to_create.source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let ip_dst = if rule_to_create.dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { rule_to_create.dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };

        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: dest_port_u16.to_be(),
            protocol: protocol_to_u8(&Some(rule_to_create.protocol.clone())),
            _pad: 0,
        };

        const ACTION_DENY: u32 = 1;
        const ACTION_ALLOW: u32 = 2;
        let action_value = if action_str == "deny" { ACTION_DENY } else { ACTION_ALLOW };

        let _ = self.blocklist.lock().await.insert(key, action_value, 0);

        info!("✅ Règle créée [ID: {}]", created_rule_id);

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
        let rule_id_to_delete = req_data.rule.map(|r| r.id).ok_or_else(|| tonic::Status::invalid_argument("ID manquant"))?;

        let row = self.db_client.query_opt("SELECT source_ip, dest_ip, dest_port, protocol FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
            .map_err(|e| tonic::Status::internal(format!("Erreur DB: {}", e)))?
            .ok_or_else(|| tonic::Status::not_found("Règle non trouvée"))?;

        let source_ip: String = row.get("source_ip");
        let dest_ip: String = row.get("dest_ip");
        let dest_port: Option<i32> = row.get("dest_port");
        let protocol: Option<String> = row.get("protocol");

        let ip_src = if source_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let ip_dst = if dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };

        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (dest_port.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&protocol),
            _pad: 0,
        };

        let _ = self.blocklist.lock().await.remove(&key);
        self.db_client.execute("DELETE FROM rules WHERE id = $1", &[&rule_id_to_delete]).await.ok();

        info!("🗑️ Règle supprimée [ID: {}]", rule_id_to_delete);

        Ok(Response::new(DeleteRuleResponse {
            delete_rule_id: rule_id_to_delete,
            message: "Règle supprimée".to_string(),
        }))
    }
    
    async fn update_rule(
        &self,
        request: Request<UpdateRuleRequest>,
    ) -> Result<Response<UpdateRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let rule_id = req_data.id;
        let new_data = req_data.rule.ok_or(tonic::Status::invalid_argument("Données manquantes"))?;
        let action_str = new_data.action.to_lowercase();
        
        // Remove old rule from BPF
        let row_old = self.db_client.query_opt("SELECT source_ip, dest_ip, dest_port, protocol FROM rules WHERE id = $1", &[&rule_id]).await.unwrap();
        if let Some(r) = row_old {
            let old_src: String = r.get("source_ip");
            let old_dst: String = r.get("dest_ip");
            let old_port: Option<i32> = r.get("dest_port");
            let old_proto: Option<String> = r.get("protocol");
            
            let ip_src = if old_src.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { old_src.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
            let ip_dst = if old_dst.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { old_dst.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };

            let key = IpPort {
                addr: u32::from(ip_src).to_be(),
                addr_dest: u32::from(ip_dst).to_be(),
                port: (old_port.unwrap_or(0) as u16).to_be(),
                protocol: protocol_to_u8(&old_proto),
                _pad: 0,
            };
            let _ = self.blocklist.lock().await.remove(&key);
        }

        // Update DB
        let src_p: Option<i32> = new_data.source_port.parse().ok();
        let dst_p: Option<i32> = new_data.dest_port.parse().ok();
        
        self.db_client.execute(
            "UPDATE rules SET name=$1, source_ip=$2, dest_ip=$3, source_port=$4, dest_port=$5, action=$6, protocol=$7 WHERE id=$8",
            &[&new_data.name, &new_data.source_ip, &new_data.dest_ip, &src_p, &dst_p, &action_str, &new_data.protocol.to_uppercase(), &rule_id]
        ).await.map_err(|e| tonic::Status::internal(format!("DB Error: {}", e)))?;

        // Insert BPF
        let ip_src = if new_data.source_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { new_data.source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let ip_dst = if new_data.dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { new_data.dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let new_key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (dst_p.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&Some(new_data.protocol.clone())),
            _pad: 0,
        };
        let act_val = if action_str == "deny" { 1 } else { 2 };
        let _ = self.blocklist.lock().await.insert(new_key, act_val, 0);

        Ok(Response::new(UpdateRuleResponse { success: true, message: "Update OK".to_string() }))
    }

    async fn get_traffic_stats(
        &self,
        request: Request<GetTrafficStatsRequest>,
    ) -> Result<Response<GetTrafficStatsResponse>, tonic::Status> {
        let req = request.into_inner();
        let range = req.time_range.trim().to_lowercase();
        
        let (interval, bucket, label) = match range.as_str() {
            "5m" | "5min" => ("5 minutes", "minute", "5 dernières minutes"),
            "1h" | "1hour" => ("1 hour", "minute", "Dernière heure"),
            "24h" | "day" => ("24 hours", "hour", "24h"),
            _ => ("100 years", "day", "Global"), 
        };

        let row_totals = self.db_client.query_one(
            &format!("SELECT COALESCE(SUM(inbound_count),0)::BIGINT as ti, COALESCE(SUM(outbound_count),0)::BIGINT as to, COALESCE(SUM(blocked_count),0)::BIGINT as tb FROM traffic_stats WHERE time > NOW() - INTERVAL '{}'", interval), 
            &[]
        ).await.map_err(|_| tonic::Status::internal("DB Error"))?;

        let rows_chart = self.db_client.query(
            &format!("WITH grid AS (SELECT generate_series(NOW() - INTERVAL '{}', NOW(), '1 {}'::interval) as bt) SELECT grid.bt, COALESCE(SUM(ts.inbound_count),0)::BIGINT as i, COALESCE(SUM(ts.outbound_count),0)::BIGINT as o, COALESCE(SUM(ts.blocked_count),0)::BIGINT as b FROM grid LEFT JOIN traffic_stats ts ON date_trunc('{}', ts.time) = date_trunc('{}', grid.bt) GROUP BY grid.bt ORDER BY grid.bt ASC", interval, bucket, bucket, bucket),
            &[]
        ).await.map_err(|_| tonic::Status::internal("DB Error"))?;

        let chart_data = rows_chart.iter().map(|r| {
            let t: SystemTime = r.get("bt");
            crate::firewall::TrafficPoint {
                timestamp: t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
                inbound: r.get("i"),
                outbound: r.get("o"),
                blocked: r.get("b"),
            }
        }).collect();

        Ok(Response::new(GetTrafficStatsResponse {
            total_inbound: row_totals.get("ti"),
            total_outbound: row_totals.get("to"),
            total_blocked: row_totals.get("tb"),
            time_period: label.to_string(),
            chart_data,
        }))
    }

    async fn watch_logs(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::WatchLogsStream>, tonic::Status> {
        info!("gRPC: Client logs connecté - Récupération historique + Live");

        // 1. Création du channel pour envoyer les logs au client gRPC
        // On augmente un peu la capacité du buffer pour encaisser l'historique
        let (tx, rx_stream) = tokio::sync::mpsc::channel(1000);

        // 2. On clone les ressources nécessaires pour la tâche asynchrone
        let db_client = self.db_client.clone();
        
        // IMPORTANT : On s'abonne au broadcast MAINTENANT pour ne pas rater de logs 
        // qui arriveraient pendant qu'on interroge la base de données.
        // Les messages seront mis en mémoire tampon dans `rx_broadcast`.
        let mut rx_broadcast = self.log_tx.subscribe();

        // 3. On lance la tâche qui va gérer le flux
        tokio::spawn(async move {
            // --- ÉTAPE A : Envoyer l'historique (Base de données) ---
            let query = "
                SELECT timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action 
                FROM traffic_logs 
                WHERE timestamp > NOW() - INTERVAL '24 hours' 
                ORDER BY timestamp ASC";

            match db_client.query(query, &[]).await {
                Ok(rows) => {
                    for row in rows {
                        // On récupère les données brutes
                        let ts: SystemTime = row.get("timestamp");
                        let src_ip: String = row.get("source_ip");
                        let dest_ip: String = row.get("dest_ip");
                        let src_port: i32 = row.get("source_port");
                        let dest_port: i32 = row.get("dest_port");
                        let proto: String = row.get("protocol");
                        let action: String = row.get("action");

                        // On reformate le message pour qu'il ressemble exactement aux logs live
                        // (Même logique que dans votre boucle principale main)
                        let level = if action == "DENY" { "WARN" } else { "INFO" };
                        let msg = format!("TRAFFIC {} | Proto: {} | {}:{} -> {}:{}", 
                            action, proto, src_ip, src_port, dest_ip, dest_port);

                        let entry = LogEntry {
                            message: msg,
                            level: level.to_string(),
                            // Note: Idéalement, utilisez chrono pour formater la date proprement
                            timestamp: format!("{:?}", ts), 
                        };

                        // Envoi au client gRPC
                        if let Err(_) = tx.send(Ok(entry)).await {
                            // Le client s'est déconnecté pendant l'envoi de l'historique
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("Erreur lors de la récupération de l'historique des logs: {}", e);
                    // On continue vers le live même si la DB échoue
                }
            }

            // --- ÉTAPE B : Envoyer le flux temps réel (Broadcast) ---
            // On consomme maintenant les messages qui se sont accumulés dans le buffer
            // du broadcast pendant qu'on lisait la DB, puis on attend les nouveaux.
            while let Ok(log_entry) = rx_broadcast.recv().await {
                if tx.send(Ok(log_entry)).await.is_err() {
                    break; // Le client s'est déconnecté
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx_stream)))
    }
}

// Fonction pour récolter les stats et les envoyer en DB
async fn collect_and_store_stats(
    stats_map: PerCpuArray<aya::maps::MapData, u64>,
    db: Arc<tokio_postgres::Client>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut prev = (0u64, 0u64, 0u64);

    loop {
        interval.tick().await;
        let mut curr = (0u64, 0u64, 0u64);

        if let Ok(v) = stats_map.get(&STAT_INBOUND, 0) { curr.0 = v.iter().sum(); }
        if let Ok(v) = stats_map.get(&STAT_OUTBOUND, 0) { curr.1 = v.iter().sum(); }
        if let Ok(v) = stats_map.get(&STAT_BLOCKED, 0) { curr.2 = v.iter().sum(); }

        let delta = (
            curr.0.saturating_sub(prev.0),
            curr.1.saturating_sub(prev.1),
            curr.2.saturating_sub(prev.2)
        );
        prev = curr;

        if delta.0 > 0 || delta.1 > 0 || delta.2 > 0 {
            let _ = db.execute(
                "INSERT INTO traffic_stats (inbound_count, outbound_count, blocked_count) VALUES ($1, $2, $3)",
                &[&(delta.0 as i64), &(delta.1 as i64), &(delta.2 as i64)],
            ).await;
        }
    }
}

// Worker pour l'insertion batch en base de données
async fn spawn_db_logger_worker(
    mut rx: tokio::sync::mpsc::Receiver<DbLogMessage>,
    db_client: Arc<tokio_postgres::Client>,
) {
    let batch_size = 500; 
    let flush_interval = std::time::Duration::from_secs(2);
    let mut buffer: Vec<DbLogMessage> = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(flush_interval);

    loop {
        tokio::select! {
            Some(log) = rx.recv() => {
                buffer.push(log);
                if buffer.len() >= batch_size {
                    flush_buffer(&db_client, &mut buffer).await;
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(&db_client, &mut buffer).await;
                }
            }
        }
    }
}

// Flush du buffer en DB (Correction E0596: on utilise prepare + execute loop au lieu de transaction pour éviter les pbs de borrowing)
async fn flush_buffer(client: &tokio_postgres::Client, buffer: &mut Vec<DbLogMessage>) {
    if buffer.is_empty() { return; }

    let stmt = match client.prepare("INSERT INTO traffic_logs (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action) VALUES ($1, $2, $3, $4, $5, $6, $7)").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SQL Prepare Error: {}", e);
            return;
        }
    };

    for log in buffer.iter() {
        if let Err(e) = client.execute(&stmt, &[
            &log.timestamp, &log.src_ip, &log.dest_ip, 
            &log.src_port, &log.dest_port, &log.protocol, &log.action
        ]).await {
            eprintln!("SQL Insert Error: {}", e);
        }
    }
    buffer.clear();
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
        .context("Erreur logger")?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-drop")))?;
    let _ = EbpfLogger::init(&mut bpf);

    let program: &mut Xdp = bpf.program_mut("xdp_firewall")
        .ok_or_else(|| anyhow::anyhow!("Programme eBPF 'xdp_firewall' introuvable"))?.try_into()?;
    program.load()?;

    // --- NOUVELLE LOGIQUE D'ATTACHEMENT MULTIPLE ---
    let interfaces = get_interfaces(&opt.iface);
    if interfaces.is_empty() {
        return Err(anyhow::anyhow!("Aucune interface réseau trouvée ou spécifiée."));
    }

    let mut attached_count = 0;
    for iface in &interfaces {
        match program.attach(iface, XdpFlags::default()) {
            Ok(_) => {
                info!(" eBPF attaché avec succès à l'interface {}.", iface);
                attached_count += 1;
            }
            Err(e) => {
                warn!("Impossible d'attacher eBPF à l'interface {} : {}", iface, e);
            }
        }
    }

    if attached_count == 0 {
        return Err(anyhow::anyhow!("Impossible d'attacher le programme eBPF. (Vérifiez les noms des interfaces)"));
    }

    let map = bpf.take_map("BLOCKLIST").ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST manquante"))?;
    let blocklist_map: HashMap<aya::maps::MapData, IpPort, u32> = HashMap::try_from(map)?;
    let blocklist = Arc::new(tokio::sync::Mutex::new(blocklist_map));

    let (pg_client_raw, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall", tokio_postgres::NoTls,
    ).await?;
    let pg_client = Arc::new(pg_client_raw);
    tokio::spawn(async move { let _ = connection.await; });

    let initial_rules = pg_client.query("SELECT id, name, source_ip, dest_ip, dest_port, action, protocol FROM rules", &[]).await?;
for row in initial_rules {
    let ip_src = if row.get::<_, String>("source_ip").to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { row.get::<_, String>("source_ip").parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
    let ip_dst = if row.get::<_, String>("dest_ip").to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { row.get::<_, String>("dest_ip").parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        
        let key = IpPort {
            addr: u32::from(ip_src).to_be(),
            addr_dest: u32::from(ip_dst).to_be(),
            port: (row.get::<_, Option<i32>>("dest_port").unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&row.get("protocol")),
            _pad: 0,
        };
        let act = if row.get::<_, String>("action").to_lowercase() == "deny" { 1 } else { 2 };
        blocklist.lock().await.insert(key, act, 0)?;
        info!("Règle chargée: {}", row.get::<_, String>("name"));
    }

    // Stats
    let stats_map_data = bpf.take_map("TRAFFIC_STATS").unwrap();
    let stats_map: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(stats_map_data)?;
    let db_cl_stats = Arc::clone(&pg_client);
    tokio::spawn(async move { collect_and_store_stats(stats_map, db_cl_stats).await; });

    // DB Logger Worker
    let (db_tx, db_rx) = tokio::sync::mpsc::channel::<DbLogMessage>(4096);
    let db_cl_logs = Arc::clone(&pg_client);
    tokio::spawn(async move { spawn_db_logger_worker(db_rx, db_cl_logs).await; });

    // Broadcast channel for gRPC
    let (log_tx, _rx) = tokio::sync::broadcast::channel(100);

    // eBPF Events Listener
    let events_map = bpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("Map EVENTS introuvable"))?;
    let mut events: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(events_map)?;
    let log_tx_events = log_tx.clone();

    for cpu_id in online_cpus().map_err(|e| anyhow::anyhow!("CPU Error: {:?}", e))? {
        let mut buf = events.open(cpu_id, None)?;
        let tx = log_tx_events.clone();
        let db_sender = db_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let ptr = buffers[i].as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };

                    let src_ip = Ipv4Addr::from(u32::from_be(data.ipv4_src));
                    let dst_ip = Ipv4Addr::from(u32::from_be(data.ipv4_dst));
                    let (act, lvl) = if data.action == 1 { ("DENY", "WARN") } else { ("ALLOW", "INFO") };
                    
                    // --- CORRECTION E0425: Variables définies ici ---
                    let proto_str = get_proto_name(data.protocol);
                    let now = SystemTime::now();
                    let src_ip_s = src_ip.to_string();
                    let dst_ip_s = dst_ip.to_string();
                    // ------------------------------------------------

                    // gRPC
                    let msg = format!("TRAFFIC {} | Proto: {} | {}:{} -> {}:{}", act, proto_str, src_ip, data.port_src, dst_ip, data.port_dst);
                    let _ = tx.send(LogEntry { message: msg, level: lvl.to_string(), timestamp: format!("{:?}", now) });

                    // DB
                    let _ = db_sender.try_send(DbLogMessage {
                        timestamp: now,
                        src_ip: src_ip_s,
                        dest_ip: dst_ip_s,
                        src_port: data.port_src as i32,
                        dest_port: data.port_dst as i32,
                        protocol: proto_str,
                        action: act.to_string(),
                    });
                }
            }
        });
    }

    let firewall_service = MyFirewallService {
        db_client: Arc::clone(&pg_client),
        blocklist: Arc::clone(&blocklist),
        log_tx,
    };

    let grpc_addr = "[::1]:50051".parse()?;
    
    info!("Serveur gRPC en écoute sur {}", grpc_addr);
    tokio::spawn(
        Server::builder()
            .add_service(FirewallServiceServer::new(firewall_service))
            .serve(grpc_addr),
    );

    signal::ctrl_c().await?;
    info!("Arrêt.");
    Ok(())
}