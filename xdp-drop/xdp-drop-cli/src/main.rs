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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> { // anyhow::Result<()> est souvent plus pratique
    let mut client = FirewallServiceClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(Empty {}); // Correct
    let response = client.get_status(request).await?;

    println!("Firewall status: {}", response.into_inner().status);

    Ok(())
}       