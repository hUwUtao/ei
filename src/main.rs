#![feature(iterator_try_collect)]

mod auto;
mod cmd;
mod config;
mod error;
mod ipset;
mod iptables;
mod rules;

use auto::{IpListManager, IpListResolver};
use clap::{Parser, Subcommand};
use config::{CliConfig, Config};
use ipset::IpsetController;
use iptables::IptablesController;
use log::{debug, error, info};
use rules::{IpListConfig, Protocol, RuleParser};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use warp::Filter;

#[derive(Parser, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to config file
    #[arg(long, default_value = "./config.toml")]
    config: PathBuf,

    /// Enable dry-run mode (print commands without executing)
    #[arg(long)]
    dry_run: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Start the daemon
    Start {
        /// Listen address for the HTTP server
        #[arg(long)]
        host: Option<String>,

        /// Listen port for the HTTP server
        #[arg(long)]
        port: Option<u16>,

        /// Enable port forwarding
        #[arg(long)]
        portforward: Option<bool>,

        /// Enable bad TCP protection
        #[arg(long)]
        badtcp: Option<bool>,

        /// Enable Docker integration
        #[arg(long)]
        docker: Option<bool>,
    },

    /// Stop the daemon
    Stop,

    /// Show current status
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct Port {
    number: u16,
    protocol: String, // "tcp" or "udp"
}

#[derive(Debug, Serialize, Deserialize)]
struct PortListResponse {
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PortResponse {
    ports: Vec<String>,
}

async fn list_ports(ipset: Arc<RwLock<IpsetController>>) -> Result<impl warp::Reply, Infallible> {
    let ipset = ipset.read().unwrap();
    match ipset.list_ports() {
        Ok(ports) => {
            let formatted_ports: Vec<String> = ports
                .into_iter()
                .map(|(port, proto)| format!("{}/{}", port, proto.to_string()))
                .collect();

            Ok(warp::reply::with_status(
                warp::reply::json(&PortResponse {
                    ports: formatted_ports,
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(_) => Ok(warp::reply::with_status(
            warp::reply::json(&"Failed to list ports"),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

#[derive(Clone)]
struct AppState {
    ipset: Arc<RwLock<IpsetController>>,
    config_path: PathBuf,
    dry_run: bool,
}

async fn load_and_configure(state: &AppState) -> Result<(), error::Error> {
    // Load configuration
    let config = Config::load(&state.config_path)?;

    // Initialize components
    let iptables = IptablesController::new(state.dry_run);
    let ipset = Arc::clone(&state.ipset);

    // Initialize rule parser
    let mut rule_parser = RuleParser::new();
    rule_parser.parse_config(&config);

    // Initialize IP list resolver and manager
    let mut resolver = IpListResolver::new();
    resolver.load_config(&config);

    let mut ip_list_manager = IpListManager::new(ipset.clone());

    // Resolve and add IP lists
    for list in resolver.resolve_all(rule_parser.get_iplist_rules().as_slice()) {
        ip_list_manager.add_list(list);
    }

    ip_list_manager.load_from_config(&config);

    resolver
        .resolve_all(rule_parser.get_whitelist_rules())
        .iter()
        .for_each(|rule| {
            ip_list_manager.register_whitelist_set(rule.name().to_string());
        });

    resolver
        .resolve_all(rule_parser.get_blacklist_rules())
        .iter()
        .for_each(|rule| {
            ip_list_manager.register_blacklist_set(rule.name().to_string());
        });

    // Update all IP lists
    ip_list_manager.update_all().await?;

    // Configure port rules
    ipset
        .write()
        .unwrap()
        .configure_port_rules(&rule_parser.get_port_rules())?;

    // Configure iptables rules
    iptables.configure_with_rules(&config, &rule_parser, &ipset.read().unwrap())?;

    Ok(())
}

async fn reload_config(state: AppState) -> Result<impl warp::Reply, Infallible> {
    match load_and_configure(&state).await {
        Ok(_) => Ok(warp::reply::with_status(
            String::from("Configuration reloaded successfully"),
            warp::http::StatusCode::OK,
        )),
        Err(e) => Ok(warp::reply::with_status(
            format!("Failed to reload configuration: {}", e),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logger
    // env_logger::init_from_env(env);
    femme::with_level(if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });

    // Load configuration
    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return;
        }
    };

    let ipset = Arc::new(RwLock::new(IpsetController::new(cli.dry_run)));

    match cli.command {
        Commands::Start {
            host,
            port,
            portforward,
            badtcp,
            docker,
        } => {
            // Update config with CLI arguments
            let mut config = config;
            config.update_from_cli(CliConfig {
                host,
                port,
                portforward,
                block_badtcp: badtcp,
                interfaces: None,
                docker,
            });

            // Save updated configuration (skip in dry-run mode)
            if !cli.dry_run {
                if let Err(e) = config.save(&cli.config) {
                    error!("Failed to save configuration: {}", e);
                    return;
                }
            }

            // Initialize controllers with dry-run mode
            let iptables = IptablesController::new(cli.dry_run);

            debug!("Applying configuration: {:?}", config);

            // Initialize and configure components
            if let Err(e) = iptables.init() {
                error!("Failed to initialize iptables: {}", e);
                return;
            }

            if let Err(e) = ipset.write().unwrap().init() {
                error!("Failed to initialize ipset: {}", e);
                return;
            }

            // Configure ipset rules
            let mut rule_parser = RuleParser::new();
            rule_parser.parse_config(&config);

            if let Err(e) = ipset
                .write()
                .unwrap()
                .configure_port_rules(&rule_parser.get_port_rules())
            {
                error!("Failed to configure port rules: {}", e);
                return;
            }

            // Configure iptables rules
            if let Err(e) =
                iptables.configure_with_rules(&config, &rule_parser, &ipset.read().unwrap())
            {
                error!("Failed to configure iptables rules: {}", e);
                return;
            }

            // Parse address
            let addr = format!("{}:{}", config.server.host, config.server.port)
                .parse()
                .expect("Invalid address");

            info!(
                "Starting server on {}:{}",
                config.server.host, config.server.port
            );
            start_daemon(ipset, addr, cli.config.clone(), cli.dry_run).await;
        }
        Commands::Stop => {
            println!("Stopping daemon (not implemented)");
        }
        Commands::Status => {
            println!("Checking status (not implemented)");
        }
    }
}

async fn start_daemon(
    ipset: Arc<RwLock<IpsetController>>,
    addr: std::net::SocketAddr,
    config_path: PathBuf,
    dry_run: bool,
) {
    let state = AppState {
        ipset: ipset.clone(),
        config_path,
        dry_run,
    };

    if let Err(e) = load_and_configure(&state).await {
        error!("Failed to apply initial configuration: {}", e);
        return;
    }

    let ipset_clone = ipset.clone();

    // GET /metrics endpoint
    let metrics = warp::path!("metrics")
        .and(warp::get())
        .map(|| "Metrics placeholder");

    // GET /ports endpoint
    let get_ports = warp::path!("ports")
        .and(warp::get())
        .and(with_ipset(ipset.clone()))
        .and_then(list_ports);

    // PUT /ports endpoint
    let put_ports = warp::path!("ports")
        .and(warp::put())
        .and(warp::body::json())
        .and(with_ipset(ipset.clone()))
        .and_then(add_port);

    // DELETE /ports endpoint
    let delete_ports = warp::path!("ports")
        .and(warp::delete())
        .and(warp::body::json())
        .and(with_ipset(ipset_clone))
        .and_then(remove_port);

    // POST /reload endpoint
    let reload = warp::path!("reload")
        .and(warp::post())
        .and(with_state(state.clone()))
        .and_then(reload_config);

    let routes = metrics
        .or(get_ports)
        .or(put_ports)
        .or(delete_ports)
        .or(reload)
        .with(warp::cors().allow_any_origin());

    warp::serve(routes).run(addr).await;
}

fn with_ipset(
    ipset: Arc<RwLock<IpsetController>>,
) -> impl Filter<Extract = (Arc<RwLock<IpsetController>>,), Error = Infallible> + Clone {
    warp::any().map(move || ipset.clone())
}

fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

async fn add_port(
    port: Port,
    ipset: Arc<RwLock<IpsetController>>,
) -> Result<impl warp::Reply, Infallible> {
    let protocol = match Protocol::try_from(port.protocol) {
        Ok(proto) => proto,
        Err(e) => {
            return Ok(warp::reply::with_status(
                e,
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    };

    match ipset.write().unwrap().add_port(port.number, protocol) {
        Ok(_) => Ok(warp::reply::with_status(
            format!("Added port {}/{}", port.number, protocol.to_string()),
            warp::http::StatusCode::OK,
        )),
        Err(e) => Ok(warp::reply::with_status(
            e.to_string(),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

async fn remove_port(
    port: Port,
    ipset: Arc<RwLock<IpsetController>>,
) -> Result<impl warp::Reply, Infallible> {
    let protocol = match Protocol::try_from(port.protocol) {
        Ok(proto) => proto,
        Err(e) => {
            return Ok(warp::reply::with_status(
                e,
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    };

    match ipset.write().unwrap().remove_port(port.number, protocol) {
        Ok(_) => Ok(warp::reply::with_status(
            format!("Removed port {}/{}", port.number, protocol.to_string()),
            warp::http::StatusCode::OK,
        )),
        Err(e) => Ok(warp::reply::with_status(
            e.to_string(),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}
