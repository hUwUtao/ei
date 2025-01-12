use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
// use std::path::PathBuf;
use std::process::exit;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// HTTP management endpoint (overrides config file)
    #[arg(long)]
    endpoint: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all ports
    List,

    /// Add a port
    Add {
        /// Port number
        #[arg(value_parser = port_in_range)]
        port: u16,

        /// Protocol (tcp/udp)
        #[arg(value_parser = parse_protocol)]
        protocol: String,
    },

    /// Remove a port
    Remove {
        /// Port number
        #[arg(value_parser = port_in_range)]
        port: u16,

        /// Protocol (tcp/udp)
        #[arg(value_parser = parse_protocol)]
        protocol: String,
    },

    /// Show metrics
    Metrics,

    /// Reload configuration
    Reload,
}

#[derive(Debug, Serialize, Deserialize)]
struct Port {
    number: u16,
    protocol: String,
}

fn port_in_range(s: &str) -> Result<u16, String> {
    let port: u16 = s.parse().map_err(|_| "Port must be a number")?;
    if port == 0 {
        return Err("Port cannot be 0".to_string());
    }
    Ok(port)
}

fn parse_protocol(s: &str) -> Result<String, String> {
    let protocol = s.to_lowercase();
    if protocol != "tcp" && protocol != "udp" {
        return Err("Protocol must be either 'tcp' or 'udp'".to_string());
    }
    Ok(protocol)
}

// #[cfg(unix)]
// fn find_config() -> Option<PathBuf> {
//     // Check current directory first
//     let current_dir = env::current_dir().ok()?;
//     let local_config = current_dir.join("config.toml");
//     if local_config.exists() {
//         return Some(local_config);
//     }

//     // Check user config directory
//     if let Some(user_config_dir) = dirs::config_dir() {
//         let user_config = user_config_dir.join("ei/config.toml");
//         if user_config.exists() {
//             return Some(user_config);
//         }
//     }

//     // Check system-wide config
//     let system_config = PathBuf::from("/etc/ei/config.toml");
//     if system_config.exists() {
//         return Some(system_config);
//     }

//     None
// }

// #[cfg(windows)]
// fn find_config() -> Option<PathBuf> {
//     None
// }

#[derive(Debug, Serialize, Deserialize)]
struct ClientConfig {
    endpoint: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            endpoint: String::from("http://127.0.0.1:8990"),
        }
    }
}

impl ClientConfig {
    #[cfg(unix)]
    fn load() -> Self {
        if let Some(config_path) = find_config() {
            if let Ok(content) = std::fs::read_to_string(config_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }
        ClientConfig::default()
    }

    #[cfg(windows)]
    fn load() -> Self {
        ClientConfig::default()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = ClientConfig::load();
    
    // Use endpoint from CLI if provided, otherwise use from config
    let endpoint = cli.endpoint.unwrap_or(config.endpoint);
    let client = Client::new();

    match cli.command {
        Commands::List => {
            match list_ports(&client, &endpoint).await {
                Ok(ports) => println!("{}", ports),
                Err(e) => {
                    eprintln!("Failed to list ports: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Add { port, protocol } => {
            match add_port(&client, &endpoint, port, &protocol).await {
                Ok(response) => println!("{}", response),
                Err(e) => {
                    eprintln!("Failed to add port: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Remove { port, protocol } => {
            match remove_port(&client, &endpoint, port, &protocol).await {
                Ok(response) => println!("{}", response),
                Err(e) => {
                    eprintln!("Failed to remove port: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Metrics => {
            match get_metrics(&client, &endpoint).await {
                Ok(metrics) => println!("{}", metrics),
                Err(e) => {
                    eprintln!("Failed to get metrics: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Reload => {
            match reload_config(&client, &endpoint).await {
                Ok(response) => println!("{}", response),
                Err(e) => {
                    eprintln!("Failed to reload configuration: {}", e);
                    exit(1);
                }
            }
        }
    }
}

async fn list_ports(client: &Client, endpoint: &str) -> Result<String, reqwest::Error> {
    let response = client
        .get(&format!("{}/ports", endpoint))
        .send()
        .await?
        .text()
        .await?;
    Ok(response)
}

async fn add_port(
    client: &Client,
    endpoint: &str,
    port: u16,
    protocol: &str,
) -> Result<String, reqwest::Error> {
    let port_data = Port {
        number: port,
        protocol: protocol.to_string(),
    };

    let response = client
        .put(&format!("{}/ports", endpoint))
        .json(&port_data)
        .send()
        .await?
        .text()
        .await?;
    Ok(response)
}

async fn remove_port(
    client: &Client,
    endpoint: &str,
    port: u16,
    protocol: &str,
) -> Result<String, reqwest::Error> {
    let port_data = Port {
        number: port,
        protocol: protocol.to_string(),
    };

    let response = client
        .delete(&format!("{}/ports", endpoint))
        .json(&port_data)
        .send()
        .await?
        .text()
        .await?;
    Ok(response)
}

async fn get_metrics(client: &Client, endpoint: &str) -> Result<String, reqwest::Error> {
    let response = client
        .get(&format!("{}/metrics", endpoint))
        .send()
        .await?
        .text()
        .await?;
    Ok(response)
}

async fn reload_config(client: &Client, endpoint: &str) -> Result<String, reqwest::Error> {
    let response = client
        .post(&format!("{}/reload", endpoint))
        .send()
        .await?
        .text()
        .await?;
    Ok(response)
}