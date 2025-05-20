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
use google::protobuf::Empty; // Maintenant cela devrait fonctionner

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Récupère le statut actuel du firewall
    Status,
    // Vous pourrez ajouter d'autres sous-commandes ici
    // Par exemple:
    // /// Ajoute une nouvelle règle au firewall
    // AddRule {
    //     #[clap(long)]
    //     ip: String,
    //     #[clap(long)]
    //     port: u16,
    // },
}


// Fonction pour gérer l'action "status"
async fn handle_get_status(client: &mut FirewallServiceClient<tonic::transport::Channel>) -> Result<(), Box<dyn std::error::Error>> {
    let request = tonic::Request::new(Empty {});
    let response = client.get_status(request).await?;
    println!("Firewall status: {}", response.into_inner().status);
    Ok(())
}

// Exemple d'une autre action (ne fait rien pour l'instant, juste pour montrer la structure)
// async fn handle_add_rule(client: &mut FirewallServiceClient<tonic::transport::Channel>, ip: String, port: u16) -> Result<(), Box<dyn std::error::Error>> {
//     println!("Demande d'ajout de règle pour IP: {}, Port: {}", ip, port);
//     // Ici, vous feriez l'appel gRPC correspondant
//     // Par exemple, si vous aviez une méthode AddRule dans votre .proto :
//     // let request = tonic::Request::new(firewall::AddRuleRequest { ip_address: ip, port_number: port as u32 });
//     // client.add_rule(request).await?;
//     // println!("Règle ajoutée (simulation).");
//     Ok(())
// }


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Se connecter au serveur gRPC une seule fois
    // Note : Vous pourriez vouloir rendre l'adresse du serveur configurable via clap aussi !
    let mut client = FirewallServiceClient::connect("http://[::1]:50051").await
        .map_err(|e| {
            eprintln!("Erreur de connexion au serveur gRPC : {}", e);
            eprintln!("Assurez-vous que le serveur firewall est lancé sur http://[::1]:50051.");
            e // retourne l'erreur originale pour la propagation
        })?;

    // Exécuter la commande appropriée
    match cli.command {
        Commands::Status => {
            handle_get_status(&mut client).await?;
        }
        // Commands::AddRule { ip, port } => {
        //     handle_add_rule(&mut client, ip, port).await?;
        // }
    }

    Ok(())
} 