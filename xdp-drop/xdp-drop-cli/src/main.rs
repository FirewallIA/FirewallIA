// Module pour le service firewall
pub mod firewall {
    tonic::include_proto!("firewall");
}

// Module pour les types Google Protobuf
pub mod google {
    pub mod protobuf {
        tonic::include_proto!("google.protobuf");
    }
}

// Importer les types nécessaires
use firewall::firewall_service_client::FirewallServiceClient;
use firewall::{RuleInfo, RuleListResponse}; // Importer les nouveaux types
use google::protobuf::Empty;
use clap::Parser;

/// Une CLI simple pour interagir avec le service Firewall gRPC
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    /// Adresse du serveur gRPC du firewall
    #[clap(long, default_value = "http://[::1]:50051")]
    server_addr: String,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Récupère le statut actuel du firewall
    Status,
    /// Liste toutes les règles actives du firewall
    ListRules, // Nouvelle sous-commande
    // ... futures commandes
    CreateRule {
        #[clap(long)]
        source_ip: String,
        #[clap(long)]
        dest_ip: String,
        #[clap(long, default_value = "*")]
        source_port: String,
        #[clap(long, default_value = "*")]
        dest_port: String,
        #[clap(long)]
        action: String, // "allow" ou "deny"
        #[clap(long, default_value = "any")]
        protocol: String,
    },
}

async fn handle_get_status(client: &mut FirewallServiceClient<tonic::transport::Channel>) -> anyhow::Result<()> {
    let request = tonic::Request::new(Empty {});
    let response = client.get_status(request).await?.into_inner();
    println!("Firewall status: {}", response.status);
    Ok(())
}

// Nouvelle fonction pour gérer la commande list-rules
async fn handle_list_rules(client: &mut FirewallServiceClient<tonic::transport::Channel>) -> anyhow::Result<()> {
    let request = tonic::Request::new(Empty {});
    let response = client.list_rules(request).await?.into_inner();

    if response.rules.is_empty() {
        println!("Aucune règle active trouvée.");
    } else {
        println!("Règles actives du firewall :");
        println!("{:<5} | {:<18} | {:<18} | {:<10} | {:<10} | {:<8} | {:<8} | {:<5}",
                 "ID", "Source IP", "Dest IP", "Src Port", "Dest Port", "Action", "Proto", "Hits");
        println!("{}", "-".repeat(100)); // Séparateur
        for rule in response.rules {
            println!("{:<5} | {:<18} | {:<18} | {:<10} | {:<10} | {:<8} | {:<8} | {:<5}",
                     rule.id,
                     rule.source_ip,
                     rule.dest_ip,
                     rule.source_port,
                     rule.dest_port,
                     rule.action,
                     rule.protocol,
                     rule.usage_count);
        }
    }
    Ok(())
}

async fn handle_create_rule(
     client: &mut FirewallServiceClient<tonic::transport::Channel>,
    rule_data: RuleData,
) -> anyhow::Result<()> {
    let request_payload = CreateRuleRequest {
        rule: Some(rule_data),
    };
    let request = tonic::Request::new(request_payload);

    let response = client.create_rule(request).await?.into_inner();

    println!(
        "Réponse du serveur: ID={}, Message='{}'",
        response.created_rule_id, response.message
    );
    Ok(())
}


#[tokio::main]
async fn main() -> anyhow::Result<()> { // Utilisation de anyhow::Result
    let cli = Cli::parse();

    let mut client = FirewallServiceClient::connect(cli.server_addr.clone()).await
        .map_err(|e| {
            eprintln!("Erreur de connexion au serveur gRPC à l'adresse '{}': {}", cli.server_addr, e);
            eprintln!("Assurez-vous que le serveur firewall est lancé et accessible.");
            anyhow::anyhow!("Connexion au serveur gRPC échouée: {}", e) // Convertir en anyhow::Error
        })?;

    match cli.command {
        Commands::Status => {
            handle_get_status(&mut client).await?;
        }
        Commands::ListRules => { // Gérer la nouvelle commande
            handle_list_rules(&mut client).await?;
        }
        Commands::CreateRule { // Variante de l'enum
            source_ip,         // Déstructuration des champs nommés
            dest_ip,
            source_port,
            dest_port,
            action,
            protocol,
        } => {                 // Bloc de code pour cette branche
            // Le compilateur va vous dire que RuleData n'est pas trouvé ici ensuite
            // car il n'est pas importé.
            let rule_data = firewall::RuleData { // <--- Préciser firewall::RuleData
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                action,
                protocol,
            };
            handle_create_rule(&mut client, rule_data).await?;
        }
    }

    Ok(())
}