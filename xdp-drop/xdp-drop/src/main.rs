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
use log::{info, warn};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tonic::{transport::Server, Request, Response};
use xdp_drop_common::{IpPort, PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use xdp_drop_common::{STAT_INBOUND, STAT_OUTBOUND, STAT_BLOCKED};
use std::time::SystemTime;

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
// --- CORRECTION 1 : Ajout des imports UpdateRuleRequest et UpdateRuleResponse ---
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
            name: name_str,
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

        let ip_src = if rule_to_create.source_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            rule_to_create.source_ip.parse().map_err(|_| tonic::Status::invalid_argument("IP Source invalide"))?
        };

        let ip_dst = if rule_to_create.dest_ip.to_lowercase() == "any" {
            Ipv4Addr::UNSPECIFIED
        } else {
            rule_to_create.dest_ip.parse().map_err(|_| tonic::Status::invalid_argument("IP Dest invalide"))?
        };

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

        match self.blocklist.lock().await.insert(key, action_value, 0) {
            Ok(_) => info!("Règle ajoutée au noyau (Hot-Reload)"),
            Err(e) => {
                log::error!("CRITIQUE: Règle ajoutée en DB mais échec BPF: {}", e);
            }
        }

        info!(
            "✅ Règle créée [ID: {} | Nom: {}] : {} -> {} | Port Dest: {} | Proto: {} | Action: {}",
            created_rule_id, rule_to_create.name, rule_to_create.source_ip, rule_to_create.dest_ip,
            dest_port_db.map_or("*".to_string(), |p| p.to_string()), rule_to_create.protocol, action_str
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
        let rule_id_to_delete = req_data.rule.map(|r| r.id)
            .ok_or_else(|| tonic::Status::invalid_argument("Données de suppression manquantes"))?;

        let row_opt = self.db_client.query_opt("SELECT source_ip, dest_ip, dest_port, protocol FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
            .map_err(|e| tonic::Status::internal(format!("Erreur récupération règle: {}", e)))?;

        let row = row_opt.ok_or_else(|| {
            tonic::Status::not_found(format!("Règle ID {} non trouvée", rule_id_to_delete))
        })?;

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

        {
            let mut map = self.blocklist.lock().await;
            if map.remove(&key).is_ok() {
                info!("Règle supprimée du noyau (Hot-Reload): {:?}", key);
            } else {
                warn!("Tentative de suppression BPF échouée (clé non trouvée ?): {:?}", key);
            }
        }
        
        self.db_client.execute("DELETE FROM rules WHERE id = $1", &[&rule_id_to_delete]).await
            .map_err(|e| tonic::Status::internal(format!("Erreur suppression DB: {}", e)))?;

        info!("Règle supprimée [ID: {}] : {} -> {}", rule_id_to_delete, source_ip, dest_ip);

        Ok(Response::new(DeleteRuleResponse {
            delete_rule_id: rule_id_to_delete,
            message: format!("Règle ID {} supprimée avec succès.", rule_id_to_delete),
        }))
    }
    
    async fn update_rule(
        &self,
        request: Request<UpdateRuleRequest>,
    ) -> Result<Response<UpdateRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let rule_id = req_data.id;
        
        let new_rule_data = req_data
            .rule
            .ok_or_else(|| tonic::Status::invalid_argument("Données de la règle manquantes"))?;

        if new_rule_data.source_ip.is_empty() || new_rule_data.dest_ip.is_empty() {
            return Err(tonic::Status::invalid_argument("Les IPs ne peuvent pas être vides"));
        }
        let action_str = new_rule_data.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(tonic::Status::invalid_argument("Action invalide (allow/deny)"));
        }

        // --- ÉTAPE A : Récupérer l'ancienne règle ---
        let row_old = self.db_client
            .query_opt("SELECT source_ip, dest_ip, dest_port, protocol FROM rules WHERE id = $1", &[&rule_id])
            .await
            .map_err(|e| tonic::Status::internal(format!("Erreur DB lecture: {}", e)))?;

        let row_old = match row_old {
            Some(r) => r,
            None => return Err(tonic::Status::not_found(format!("Règle ID {} introuvable", rule_id))),
        };

        let old_src_ip: String = row_old.get("source_ip");
        let old_dest_ip: String = row_old.get("dest_ip");
        let old_dest_port: Option<i32> = row_old.get("dest_port");
        let old_protocol: Option<String> = row_old.get("protocol");

        // --- ÉTAPE B : Suppression eBPF ---
        let old_ip_src = if old_src_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { old_src_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let old_ip_dst = if old_dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { old_dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        
        let old_key = IpPort {
            addr: u32::from(old_ip_src).to_be(),
            addr_dest: u32::from(old_ip_dst).to_be(),
            port: (old_dest_port.unwrap_or(0) as u16).to_be(),
            protocol: protocol_to_u8(&old_protocol),
            _pad: 0,
        };

        {
            let mut map = self.blocklist.lock().await;
            if map.remove(&old_key).is_ok() {
                info!("🔄 Update (1/2): Ancienne règle eBPF supprimée");
            } else {
                warn!("⚠️ Update (1/2): Ancienne règle introuvable dans eBPF, continuation...");
            }
        }

        // --- ÉTAPE C : Mise à jour DB ---
        let new_src_port_db: Option<i32> = new_rule_data.source_port.parse().ok();
        let new_dest_port_db: Option<i32> = new_rule_data.dest_port.parse().ok();
        let new_dest_port_u16 = new_dest_port_db.unwrap_or(0) as u16;

        let update_query = "
            UPDATE rules 
            SET name=$1, source_ip=$2, dest_ip=$3, source_port=$4, dest_port=$5, action=$6, protocol=$7
            WHERE id=$8
        ";
        
        let rows_affected = self.db_client.execute(
            update_query,
            &[
                &new_rule_data.name, &new_rule_data.source_ip, &new_rule_data.dest_ip,
                &new_src_port_db, &new_dest_port_db, &action_str,
                &new_rule_data.protocol.to_uppercase(), &rule_id
            ]
        ).await.map_err(|e| tonic::Status::internal(format!("Erreur update DB: {}", e)))?;

        if rows_affected == 0 {
             return Err(tonic::Status::not_found("Impossible de mettre à jour la DB (ID introuvable ?)"));
        }

        // --- ÉTAPE D : Insertion eBPF ---
        let new_ip_src = if new_rule_data.source_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { new_rule_data.source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };
        let new_ip_dst = if new_rule_data.dest_ip.to_lowercase() == "any" { Ipv4Addr::UNSPECIFIED } else { new_rule_data.dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED) };

        let new_key = IpPort {
            addr: u32::from(new_ip_src).to_be(),
            addr_dest: u32::from(new_ip_dst).to_be(),
            port: new_dest_port_u16.to_be(),
            protocol: protocol_to_u8(&Some(new_rule_data.protocol.clone())),
            _pad: 0,
        };

        const ACTION_DENY: u32 = 1;
        const ACTION_ALLOW: u32 = 2;
        let action_value = if action_str == "deny" { ACTION_DENY } else { ACTION_ALLOW };

        {
            let mut map = self.blocklist.lock().await;
            match map.insert(new_key, action_value, 0) {
                Ok(_) => info!("Update (2/2): Nouvelle règle eBPF ajoutée"),
                Err(e) => log::error!("Update CRITIQUE: Échec insertion eBPF: {}", e),
            }
        }

        info!("Règle ID {} mise à jour avec succès", rule_id);

        Ok(Response::new(UpdateRuleResponse {
            success: true,
            message: "Règle mise à jour avec succès".to_string(),
        }))
    }

    // --- CORRECTION 2 : get_traffic_stats est maintenant DANS le bloc impl ---
    async fn get_traffic_stats(
        &self,
        request: Request<GetTrafficStatsRequest>,
    ) -> Result<Response<GetTrafficStatsResponse>, tonic::Status> {
        let req = request.into_inner();
        let range_input = req.time_range.trim().to_lowercase();
        
        info!("gRPC: Demande de stats (Range: '{}')", range_input);

        let (sql_interval, bucket_size, period_label) = match range_input.as_str() {
            "5m" | "5min" => ("5 minutes", "minute", "5 dernières minutes"),
            "1h" | "1hour" => ("1 hour", "minute", "Dernière heure"),
            "4h" | "4hours" => ("4 hours", "minute", "4 dernières heures"),
            "12h" | "12hours" => ("12 hours", "hour", "12 dernières heures"),
            "24h" | "day" => ("24 hours", "hour", "Dernières 24 heures"),
            "7d" | "1w" | "week" => ("1 week", "day", "Dernière semaine"),
            "30d" | "month" => ("1 month", "day", "Dernier mois"),
            _ => ("100 years", "day", "Global (Historique complet)"), 
        };

        let query_totals = format!(
            "SELECT 
                COALESCE(SUM(inbound_count), 0)::BIGINT as total_in, 
                COALESCE(SUM(outbound_count), 0)::BIGINT as total_out, 
                COALESCE(SUM(blocked_count), 0)::BIGINT as total_blocked 
            FROM traffic_stats 
            WHERE time > NOW() - INTERVAL '{}'",
            sql_interval
        );

        let row_totals = self.db_client.query_one(query_totals.as_str(), &[])
            .await
            .map_err(|e| {
                log::error!("Erreur SQL Totals: {}", e);
                tonic::Status::internal("Erreur DB")
            })?;

        let query_chart = format!(
            "WITH grid AS (
                SELECT generate_series(
                    NOW() - INTERVAL '{}', 
                    NOW(), 
                    '1 {}'::interval
                ) as bucket_time
            )
            SELECT 
                grid.bucket_time,
                COALESCE(SUM(ts.inbound_count), 0)::BIGINT as inc, 
                COALESCE(SUM(ts.outbound_count), 0)::BIGINT as outc, 
                COALESCE(SUM(ts.blocked_count), 0)::BIGINT as blkc 
            FROM grid
            LEFT JOIN traffic_stats ts 
            ON date_trunc('{}', ts.time) = date_trunc('{}', grid.bucket_time)
            GROUP BY grid.bucket_time
            ORDER BY grid.bucket_time ASC",
            sql_interval, bucket_size, bucket_size, bucket_size
        );

        let rows_chart = self.db_client.query(query_chart.as_str(), &[])
            .await
            .map_err(|e| {
                log::error!("Erreur SQL Chart: {}", e);
                tonic::Status::internal("Erreur DB Chart")
            })?;

        let mut chart_data_vec = Vec::new();
        for row in rows_chart {
            let time_val: SystemTime = row.get("bucket_time");
            let timestamp = time_val.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            chart_data_vec.push(crate::firewall::TrafficPoint {
                timestamp,
                inbound: row.get("inc"),
                outbound: row.get("outc"),
                blocked: row.get("blkc"),
            });
        }

        Ok(Response::new(GetTrafficStatsResponse {
            total_inbound: row_totals.get("total_in"),
            total_outbound: row_totals.get("total_out"),
            total_blocked: row_totals.get("total_blocked"),
            time_period: period_label.to_string(),
            chart_data: chart_data_vec,
        }))
    }
}

// Fonction pour récolter les stats et les envoyer en DB
async fn collect_and_store_stats(
    stats_map: PerCpuArray<aya::maps::MapData, u64>,
    db: Arc<tokio_postgres::Client>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut prev_inbound = 0u64;
    let mut prev_outbound = 0u64;
    let mut prev_blocked = 0u64;

    loop {
        interval.tick().await;

        let mut curr_inbound = 0u64;
        let mut curr_outbound = 0u64;
        let mut curr_blocked = 0u64;

        if let Ok(values) = stats_map.get(&STAT_INBOUND, 0) { curr_inbound = values.iter().sum(); }
        if let Ok(values) = stats_map.get(&STAT_OUTBOUND, 0) { curr_outbound = values.iter().sum(); }
        if let Ok(values) = stats_map.get(&STAT_BLOCKED, 0) { curr_blocked = values.iter().sum(); }

        let delta_inbound = curr_inbound.saturating_sub(prev_inbound);
        let delta_outbound = curr_outbound.saturating_sub(prev_outbound);
        let delta_blocked = curr_blocked.saturating_sub(prev_blocked);

        prev_inbound = curr_inbound;
        prev_outbound = curr_outbound;
        prev_blocked = curr_blocked;

        if delta_inbound > 0 || delta_outbound > 0 || delta_blocked > 0 {
            let res = db.execute(
                "INSERT INTO traffic_stats (inbound_count, outbound_count, blocked_count) VALUES ($1, $2, $3)",
                &[&(delta_inbound as i64), &(delta_outbound as i64), &(delta_blocked as i64)],
            ).await;
            if let Err(e) = res { log::error!("Erreur insertion stats DB: {}", e); }
        }
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
        .ok_or_else(|| anyhow::anyhow!("Programme eBPF 'xdp_firewall' introuvable"))?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    info!("eBPF program loaded and attached to {}.", opt.iface);

    let map = bpf.take_map("BLOCKLIST").ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST introuvable"))?;
    let blocklist_map: HashMap<aya::maps::MapData, IpPort, u32> = HashMap::try_from(map)?;
    let blocklist: Arc<tokio::sync::Mutex<HashMap<aya::maps::MapData, IpPort, u32>>> = Arc::new(tokio::sync::Mutex::new(blocklist_map));

    let (pg_client_raw, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall", tokio_postgres::NoTls,
    ).await?;
    let pg_client = Arc::new(pg_client_raw);
    tokio::spawn(async move { let _ = connection.await; });

    let initial_rules = pg_client.query("SELECT id, name, source_ip, dest_ip, dest_port, action, protocol FROM rules", &[]).await?;
    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2;

    info!("--- Chargement des règles au démarrage ---");
    for row in initial_rules {
        let id: i32 = row.get("id");
        let name: String = row.get("name");
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
        let action_value = match action.to_lowercase().as_str() {
            "deny" => ACTION_DENY,
            "allow" => ACTION_ALLOW,
            _ => continue,
        };

        blocklist.lock().await.insert(key, action_value, 0)?;
        info!("📜 Règle chargée [ID: {} | {}]", id, name);
    }

    let stats_map_data = bpf.take_map("TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("Map TRAFFIC_STATS introuvable dans le programme eBPF"))?;
    let stats_map: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(stats_map_data)?;
    let db_client_for_stats = Arc::clone(&pg_client);

    tokio::spawn(async move {
        collect_and_store_stats(stats_map, db_client_for_stats).await;
    });

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