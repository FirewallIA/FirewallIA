use tonic::transport::Channel;
use firewall::firewall_service_client::FirewallServiceClient;
use firewall::Empty;

pub mod firewall {
    tonic::include_proto!("firewall");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = FirewallServiceClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(Empty {});
    let response = client.get_status(request).await?;

    println!("Firewall status: {}", response.into_inner().status);

    Ok(())
}
