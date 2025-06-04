use anyhow::Context;
use aya::{
    Bpf,
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData}, // Renommer pour éviter conflit avec std::collections::HashMap
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::{Parser, CommandFactory};
use flexi_logger::{Duplicate, FileSpec, Logger};
use log::{info, warn, error}; // error
use std::sync::Arc;
use std::time::Duration; // Pour le cleanup
use tokio::signal;
use tokio::time::interval; // Pour le cleanup
use tonic::{transport::Server, Request, Response, Status};

// Importer les nouvelles structures
use xdp_drop_common::{IpPort, ConnectionKey, ConnectionValue, TcpState, UdpState, ConnStateVariant};


// ... (reste de vos imports et modules firewall, google)
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
    // On a besoin d'un accès à la map BLOCKLIST pour Create/Delete Rule
    // Et potentiellement à CONN_TRACK_TABLE si on veut effacer des états lors de la suppression de règles
    bpf_blocklist_map: Arc<tokio::sync::Mutex<AyaHashMap<MapData, IpPort, u32>>>,
    // bpf_ctt_map: Arc<tokio::sync::Mutex<AyaHashMap<MapData, ConnectionKey, ConnectionValue>>>, // Si besoin
}

// Fonction pour récupérer et formater les règles (existante, inchangée)
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
    async fn get_status( /* ... */ &self, request: Request<Empty>) -> Result<Response<FirewallStatus>, Status> {
        info!("gRPC: Appel de GetStatus reçu");
        let status = FirewallStatus {
            status: "UP".to_string(),
        };
        Ok(Response::new(status))
    }

    async fn list_rules( /* ... */ &self, request: Request<Empty>) -> Result<Response<RuleListResponse>, Status> {
        info!("gRPC: Appel de ListRules reçu");
        match fetch_and_format_rules_from_db(&self.db_client).await {
            Ok(rules) => Ok(Response::new(RuleListResponse { rules })),
            Err(e) => {
                error!("Erreur lors de la récupération des règles pour gRPC: {}", e);
                Err(Status::internal(format!("Échec de la récupération des règles: {}", e)))
            }
        }
    }

    async fn create_rule(
        &self,
        request: Request<CreateRuleRequest>,
    ) -> Result<Response<CreateRuleResponse>, tonic::Status> {
        let req_data = request.into_inner();
        info!("gRPC: Appel de CreateRule reçu pour : {:?}", req_data.rule);

        let rule_to_create = req_data.rule.ok_or_else(|| Status::invalid_argument("Données de règle manquantes"))?;

        // Validations (simples)
        if rule_to_create.source_ip.is_empty() || rule_to_create.dest_ip.is_empty() {
            return Err(Status::invalid_argument("IPs source/dest requises."));
        }
        let action_str = rule_to_create.action.to_lowercase();
        if action_str != "allow" && action_str != "deny" {
            return Err(Status::invalid_argument("Action doit être 'allow' ou 'deny'."));
        }
        let source_port_db: Option<i32> = rule_to_create.source_port.parse().ok();
        let dest_port_db: Option<i32> = rule_to_create.dest_port.parse().ok();

        // Insertion DB
        let created_rule_id: i32 = match self.db_client.query_one(
            "INSERT INTO rules (source_ip, dest_ip, source_port, dest_port, action, protocol) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[
                &rule_to_create.source_ip, &rule_to_create.dest_ip,
                &source_port_db, &dest_port_db,
                &action_str, &rule_to_create.protocol.to_uppercase(),
            ],
        ).await {
            Ok(row) => row.get(0),
            Err(e) => {
                error!("DB Insert error: {}", e);
                return Err(Status::internal(format!("DB error: {}", e)));
            }
        };
        info!("Règle insérée dans DB ID: {}", created_rule_id);

        // Insertion dans la map eBPF `BLOCKLIST`
        const ACTION_DENY_U32: u32 = 1;
        const ACTION_ALLOW_U32: u32 = 2;
        match (rule_to_create.source_ip.parse::<std::net::Ipv4Addr>(), rule_to_create.dest_ip.parse::<std::net::Ipv4Addr>()) {
            (Ok(ip_src_obj), Ok(ip_dst_obj)) => {
                let port_for_bpf = if rule_to_create.dest_port == "*" || rule_to_create.dest_port.is_empty() {
                     0 // Wildcard port
                } else {
                    rule_to_create.dest_port.parse().unwrap_or(0) // Port spécifique, ou 0 si invalide
                };

                let key_bpf = IpPort {
                    addr: u32::from(ip_src_obj).to_be(),
                    addr_dest: u32::from(ip_dst_obj).to_be(),
                    port: port_for_bpf.to_be(), // port en network byte order
                    _pad: 0,
                };
                let action_value_bpf = if action_str == "deny" { ACTION_DENY_U32 } else { ACTION_ALLOW_U32 };

                let mut blocklist_map_guard = self.bpf_blocklist_map.lock().await;
                match blocklist_map_guard.insert(key_bpf, action_value_bpf, 0) {
                    Ok(_) => info!("Règle ID {} insérée/mise à jour dans la map BPF BLOCKLIST.", created_rule_id),
                    Err(e) => {
                        error!("Erreur d'insertion dans BPF BLOCKLIST pour règle ID {}: {}", created_rule_id, e);
                        // Peut-être annuler l'insertion DB ou marquer la règle comme inactive?
                        // Pour l'instant, on continue mais on logue l'erreur.
                    }
                }
            }
            _ => {
                warn!("IPs invalides pour l'insertion BPF, règle ID {}: {} -> {}", created_rule_id, rule_to_create.source_ip, rule_to_create.dest_ip);
            }
        }

        Ok(Response::new(CreateRuleResponse {
            created_rule_id,
            message: format!("Règle créée ID {}.", created_rule_id),
        }))
    }

    async fn delete_rule(
        &self,
        request: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, tonic::Status> {
        let rule_id_to_delete = request.into_inner().rule
            .ok_or_else(|| Status::invalid_argument("Données de suppression manquantes"))?
            .id;
        info!("gRPC: Appel de DeleteRule pour ID: {}", rule_id_to_delete);

        // 1. Récupérer les infos de la règle depuis la DB pour la clé BPF
        let (source_ip_str, dest_ip_str, dest_port_opt_db) : (String, String, Option<i32>) =
            match self.db_client.query_opt(
                "SELECT source_ip, dest_ip, dest_port FROM rules WHERE id = $1",
                &[&rule_id_to_delete]
            ).await {
                Ok(Some(row)) => (row.get(0), row.get(1), row.get(2)),
                Ok(None) => return Err(Status::not_found(format!("Règle ID {} non trouvée.", rule_id_to_delete))),
                Err(e) => {
                    error!("DB Select error for delete: {}", e);
                    return Err(Status::internal(format!("DB error: {}", e)));
                }
            };

        // 2. Suppression de la map eBPF BLOCKLIST
        match (source_ip_str.parse::<std::net::Ipv4Addr>(), dest_ip_str.parse::<std::net::Ipv4Addr>()) {
            (Ok(ip_src_obj), Ok(ip_dst_obj)) => {
                 let port_for_bpf = dest_port_opt_db.map_or(0, |p| p as u16); // 0 pour wildcard si NULL

                let key_bpf = IpPort {
                    addr: u32::from(ip_src_obj).to_be(),
                    addr_dest: u32::from(ip_dst_obj).to_be(),
                    port: port_for_bpf.to_be(),
                    _pad: 0,
                };
                let mut blocklist_map_guard = self.bpf_blocklist_map.lock().await;
                match blocklist_map_guard.remove(&key_bpf) {
                    Ok(_) => info!("Règle ID {} (clé BPF {:?}) supprimée de BLOCKLIST.", rule_id_to_delete, key_bpf),
                    Err(e) => warn!("Erreur ou clé non trouvée lors de la suppression BPF BLOCKLIST pour ID {}: {} (clé {:?})", rule_id_to_delete, e, key_bpf),
                }
            }
            _ => {
                warn!("IPs invalides pour la suppression BPF, règle ID {}", rule_id_to_delete);
            }
        }
        // NOTE: On ne nettoie PAS la CONN_TRACK_TABLE ici pour la simplicité.
        // Les connexions existantes autorisées par cette règle continueront jusqu'à leur timeout.
        // Pour un comportement plus strict, il faudrait itérer CONN_TRACK_TABLE et supprimer les entrées correspondantes.

        // 3. Suppression de la base de données PostgreSQL
        match self.db_client.execute("DELETE FROM rules WHERE id = $1", &[&rule_id_to_delete]).await {
            Ok(0) => return Err(Status::not_found(format!("Règle ID {} non trouvée pour suppression DB.", rule_id_to_delete))),
            Ok(_) => info!("Règle ID {} supprimée de la DB.", rule_id_to_delete),
            Err(e) => {
                error!("DB Delete error: {}", e);
                return Err(Status::internal(format!("DB error: {}", e)));
            }
        }

        Ok(Response::new(DeleteRuleResponse {
            delete_rule_id,
            message: format!("Règle ID {} supprimée.", rule_id_to_delete),
        }))
    }
}


// Tâche de nettoyage de la table de suivi des connexions
async fn run_ctt_cleanup_task(
    ctt_map: Arc<tokio::sync::Mutex<AyaHashMap<MapData, ConnectionKey, ConnectionValue>>>,
) {
    // Définir les timeouts (en nanosecondes)
    const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 300 * 1_000_000_000; // 5 minutes
    const TCP_TRANSIENT_TIMEOUT_NS: u64 = 60 * 1_000_000_000; // 1 minute (SYN_SENT, SYN_RECEIVED)
    const UDP_TIMEOUT_NS: u64 = 30 * 1_000_000_000; // 30 secondes
    const CLEANUP_INTERVAL_S: u64 = 10; // Exécuter le nettoyage toutes les 10 secondes

    info!("🧹 Tâche de nettoyage CTT démarrée (intervalle: {}s).", CLEANUP_INTERVAL_S);
    let mut interval_timer = interval(Duration::from_secs(CLEANUP_INTERVAL_S));

    loop {
        interval_timer.tick().await;
        info!("🧹 Exécution du nettoyage de la table de suivi des connexions...");

        let mut ctt_map_guard = ctt_map.lock().await;
        let mut keys_to_remove = Vec::new();
        let mut inspected_count = 0;
        let mut removed_count = 0;

        // Il faut obtenir l'heure actuelle d'une manière compatible avec bpf_ktime_get_ns.
        // Malheureusement, il n'y a pas d'appel direct bpf_ktime_get_ns depuis userspace.
        // Une astuce est de lire une valeur de timestamp d'une map spéciale mise à jour par eBPF,
        // ou plus simplement, on suppose que l'horloge du système userspace est raisonnablement
        // synchronisée avec celle du kernel (ce qui est généralement le cas).
        // Pour une vraie précision, il faudrait une map eBPF qui stocke juste le ktime actuel.
        // Ici, on va utiliser `SystemTime` et le convertir, en sachant qu'il peut y avoir un léger décalage.
        // La solution la plus robuste est de lire le ktime à partir d'un programme eBPF via une map.
        // Pour simplifier, on va utiliser une approximation avec l'heure système.
        // Le timestamp `bpf_ktime_get_ns` est un u64 représentant des nanosecondes monotones depuis le démarrage.
        // On va devoir faire attention si on compare directement.
        // Pour cet exemple, nous allons supposer que nous pouvons obtenir un timestamp comparable.
        // Une approche plus simple pour un POC est de se baser sur les durées et non les timestamps absolus.
        // Mais les timestamps sont déjà dans la map...
        //
        // Solution pragmatique: on ne peut pas obtenir bpf_ktime_get_ns() directement.
        // On va donc retirer les entrées si last_seen_ns est "trop vieux" par rapport à la dernière fois qu'on a regardé.
        // Mais c'est incorrect. On doit comparer à "maintenant".
        //
        // Alternative: Itérer les clés, pour chaque clé, lire la valeur. C'est ce que fait `iter()`.
        // Le `last_seen_ns` est celui écrit par eBPF.
        // On a besoin d'un "maintenant" du point de vue de `bpf_ktime_get_ns`.
        // C'est le point délicat.
        //
        // **Simplification pour cet exemple :** On va juste logguer les entrées.
        // Pour une VRAIE suppression, il faudrait un moyen fiable d'obtenir le ktime_ns actuel
        // ou que le programme eBPF lui-même marque les entrées comme périmées,
        // et que userspace les supprime.
        // Ou, alternativement, la map `LruHashMap` d'Aya gère l'expiration, mais elle est moins flexible pour les états.
        //
        // Pour une VRAIE implémentation: utiliser une map eBPF de type PERF_EVENT_ARRAY
        // pour que eBPF notifie userspace quand une entrée *devrait* être créée avec son timestamp,
        // et userspace maintient sa propre CTT avec des `Instant` Rust, et envoie des commandes
        // à eBPF pour supprimer des clés. C'est BEAUCOUP plus complexe.
        //
        // **Solution de contournement pour la démo :** On ne peut pas avoir bpf_ktime_get_ns() en user space.
        // Donc, on ne peut pas comparer directement `last_seen_ns` avec un "maintenant" équivalent.
        // Ce que font certains outils (comme conntrack-tools) est de lire les entrées et de calculer
        // une "durée de vie restante" basée sur le timeout connu pour cet état et le `last_seen_ns`.
        // Mais pour cela, il faut quand même un point de référence.
        //
        // **Option la plus simple (mais moins précise) pour la démo :**
        // Lors du nettoyage, lire toutes les entrées.
        // Si une entrée n'a pas été mise à jour depuis X cycles de nettoyage, la considérer comme vieille.
        // Ceci est très approximatif.
        //
        // **La meilleure approche avec les maps eBPF actuelles serait:**
        // En eBPF: si une entrée est trop vieille LORS D'UN ACCES, la supprimer.
        // Mais on veut un nettoyage proactif.
        //
        // Ok, compromis pour la démo : on va supposer que la différence de temps entre le dernier
        // `bpf_ktime_get_ns()` stocké et un `bpf_ktime_get_ns()` qu'on *pourrait* lire maintenant
        // est équivalente à la durée mesurée par `Instant::now()`. C'est une approximation.
        // Il est plus sûr de lire toutes les entrées et de les supprimer si elles semblent vieilles.
        // Pour ce faire, il faut itérer sur les clés, puis faire un `get` pour chaque clé.

        // On itère sur les clés d'abord, puis on récupère les valeurs pour éviter les problèmes de borrowing avec le MutexGuard
        let current_keys: Vec<ConnectionKey> = ctt_map_guard.keys().collect::<Result<_, _>>().unwrap_or_default();

        for key in current_keys {
            inspected_count += 1;
            if let Ok(Some(value)) = ctt_map_guard.get(&key, 0) { // Le flag 0 est standard
                let conn_value: ConnectionValue = value; // Aya dérive Pod, donc c'est une copie.

                // On ne peut PAS appeler bpf_ktime_get_ns() ici.
                // On va devoir utiliser une heuristique ou accepter l'imprécision.
                // Le plus simple: si une règle est supprimée en userspace, elle le sera aussi en eBPF.
                // Les timeouts ici sont pour les connexions qui se terminent "naturellement" ou sont inactives.

                // *****************************************************************************
                // DÉBUT SECTION CRITIQUE POUR LE TIMESTAMP
                // Pour une vraie implémentation, il faudrait un mécanisme pour que
                // eBPF fournisse un timestamp "actuel" à userspace, ou que userspace
                // ait une connaissance des timeouts et supprime si last_seen_ns est "vieux".
                // Ici, on va juste imprimer, car on n'a pas de `bpf_ktime_get_ns()` fiable en userspace.
                // log::trace!("CTT Entry: {:?} -> {:?} (last_seen_ns: {})", key, conn_value.state, conn_value.last_seen_ns);
                //
                // Alternative (pas implémentée ici pour garder le code plus simple pour le moment):
                // 1. Créez une map eBPF séparée (par exemple, `CURRENT_KTIME_MAP`) de type `Array` avec 1 seule entrée.
                // 2. Dans votre programme eBPF, au début de `try_xdp_firewall`, écrivez `bpf_ktime_get_ns()` dans cette map.
                // 3. En userspace, lisez cette map pour obtenir un `current_ktime_ns` quasi-actuel du kernel.
                // 4. Comparez `conn_value.last_seen_ns` avec ce `current_ktime_ns`.
                // *****************************************************************************

                // Pour la démo, on va juste simuler une expiration si on ne voit pas de mise à jour
                // sur un très grand nombre de cycles (pas idéal).
                // OU, on se fie au fait que le kernel va réutiliser les entrées de map si elle est pleine (pas idéal non plus).

                // Simplification extrême pour la démo : on ne supprime RIEN ici pour éviter des faux positifs
                // dus à la problématique du timestamp. On va juste logguer.
                // Dans un vrai système, cette partie est cruciale et doit être correcte.

                // Exemple de logique si on avait current_ktime_ns:
                /*
                let current_ktime_ns = get_current_kernel_time_somehow().await; // Fonction hypothétique
                let age_ns = current_ktime_ns.saturating_sub(conn_value.last_seen_ns);
                let timeout_ns = match conn_value.state {
                    ConnStateVariant::Tcp(TcpState::Established) => TCP_ESTABLISHED_TIMEOUT_NS,
                    ConnStateVariant::Tcp(_) => TCP_TRANSIENT_TIMEOUT_NS,
                    ConnStateVariant::Udp(_) => UDP_TIMEOUT_NS,
                };
                if age_ns > timeout_ns {
                    keys_to_remove.push(key);
                }
                */
            }
        }
        // Pour la démo, on va logguer le nombre d'entrées, mais pas supprimer activement
        // à cause du problème de timestamp.
        let map_size = ctt_map_guard.iter().count();
        info!("🧹 CTT: {} entrées inspectées. {} entrées actuellement dans la map. (Nettoyage actif désactivé pour la démo à cause du timestamp).", inspected_count, map_size);


        // Si on avait des clés à supprimer:
        // for key_to_remove in keys_to_remove {
        //     if let Err(e) = ctt_map_guard.remove(&key_to_remove) {
        //         warn!("🧹 Erreur lors de la suppression de la clé CTT {:?}: {}", key_to_remove, e);
        //     } else {
        //         removed_count += 1;
        //     }
        // }
        // if removed_count > 0 {
        //     info!("🧹 CTT: {} entrées supprimées.", removed_count);
        // }
    }
}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    validate_args(&opt);

    Logger::try_with_str("info")? /* ... */ .start().context("Logger init error")?;
    info!("Logger initialisé.");

    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-drop")))
        .context("Failed to load BPF program")?;

    if let Err(e) = EbpfLogger::init(&mut bpf) { warn!("eBPF logger init error: {}", e); }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall")
        .ok_or_else(|| anyhow::anyhow!("eBPF program 'xdp_firewall' not found"))?
        .try_into().context("Program conversion to Xdp error")?;
    program.load().context("XDP program load error")?;
    program.attach(&opt.iface, XdpFlags::default())
        .context(format!("XDP attach error to {}", opt.iface))?;
    info!("eBPF program loaded and attached to {}.", opt.iface);

    // Map pour les règles statiques
    let blocklist_bpf_map: AyaHashMap<_, IpPort, u32> =
        AyaHashMap::try_from(bpf.map_mut("BLOCKLIST").context("BLOCKLIST map not found")?)?;
    let blocklist_map_arc = Arc::new(tokio::sync::Mutex::new(blocklist_bpf_map));


    // NOUVELLE MAP: Table de suivi des connexions
    let ctt_bpf_map: AyaHashMap<_, ConnectionKey, ConnectionValue> =
        AyaHashMap::try_from(bpf.map_mut("CONN_TRACK_TABLE").context("CONN_TRACK_TABLE map not found")?)?;
    let ctt_map_arc = Arc::new(tokio::sync::Mutex::new(ctt_bpf_map));


    let (pg_client_raw, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=postgres dbname=firewall",
        tokio_postgres::NoTls,
    ).await.context("PostgreSQL connection error")?;
    info!("Connecté à PostgreSQL.");
    let pg_client = Arc::new(pg_client_raw);
    tokio::spawn(async move {
        if let Err(e) = connection.await { eprintln!("PostgreSQL background connection error: {e}"); }
    });

    info!("📋 Chargement des règles initiales (BLOCKLIST) depuis la DB...");
    let initial_rules_from_db = pg_client.query( /* ... */ "SELECT id, source_ip, dest_ip, source_port, dest_port, action, protocol, usage_count FROM rules", &[]).await
        .context("Initial rule loading error")?;

    const ACTION_DENY: u32 = 1;
    const ACTION_ALLOW: u32 = 2; // Rappel: pour initier des connexions

    { // Bloc pour le MutexGuard de blocklist_map_arc
        let mut blocklist_map_guard = blocklist_map_arc.lock().await;
        for row in initial_rules_from_db {
            let id: i32 = row.get("id");
            let source_ip: String = row.get("source_ip");
            let dest_ip: String = row.get("dest_ip");
            let _source_port: Option<i32> = row.get("source_port"); // Non utilisé dans la clé BLOCKLIST actuelle
            let dest_port_opt: Option<i32> = row.get("dest_port");
            let action: String = row.get("action");
            let _protocol: Option<String> = row.get("protocol"); // Non utilisé dans la clé BLOCKLIST actuelle

            let ip_addr = source_ip.parse::<std::net::Ipv4Addr>().context(format!("Invalid source IP for rule {id}"))?;
            let ip_dest_addr = dest_ip.parse::<std::net::Ipv4Addr>().context(format!("Invalid dest IP for rule {id}"))?;
            let port_val = dest_port_opt.unwrap_or(0) as u16; // 0 pour wildcard

            let key = IpPort {
                addr: u32::from(ip_addr).to_be(),
                addr_dest: u32::from(ip_dest_addr).to_be(),
                port: port_val.to_be(), // Port en network byte order
                _pad: 0,
            };

            let action_value = match action.to_lowercase().as_str() {
                "deny" => ACTION_DENY,
                "allow" => ACTION_ALLOW,
                _ => { warn!("Unknown action '{}' for rule #{id}, ignored.", action); continue; }
            };
            blocklist_map_guard.insert(key, action_value, 0).context(format!("BPF insert error for rule #{id}"))?;
            info!("🛡️ BLOCKLIST Rule #{id}: {} -> {}:{} | Action: {}", source_ip, dest_ip, port_val, action);
        }
    }


    // Démarrer la tâche de nettoyage CTT
    let ctt_cleanup_task_handle = tokio::spawn(run_ctt_cleanup_task(Arc::clone(&ctt_map_arc)));


    let grpc_addr = "[::1]:50051".parse().context("Invalid gRPC address")?;
    let firewall_service = MyFirewallService {
        db_client: Arc::clone(&pg_client),
        bpf_blocklist_map: Arc::clone(&blocklist_map_arc), // Passer le handle de la map
        // bpf_ctt_map: Arc::clone(&ctt_map_arc), // Si gRPC doit interagir avec CTT
    };
    info!("Service Firewall gRPC en cours de création...");
    let grpc_server_future = Server::builder()
        .add_service(FirewallServiceServer::new(firewall_service))
        .serve(grpc_addr);

    tokio::spawn(async move {
        info!("Serveur gRPC démarré sur {}", grpc_addr);
        if let Err(e) = grpc_server_future.await { eprintln!("Erreur serveur gRPC : {e}"); }
    });

    info!("🔥 Le firewall stateful est en marche !");
    info!("⏳ Appuyez sur Ctrl-C pour arrêter...");
    signal::ctrl_c().await.context("Ctrl-C signal error")?;
    info!("🛑 Arrêt du firewall...");

    ctt_cleanup_task_handle.abort(); // Arrêter la tâche de nettoyage proprement
    // Attendre un peu si nécessaire : tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}