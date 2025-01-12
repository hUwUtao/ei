use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::rules::Rule;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: ServerConfig,
    pub features: FeaturesConfig,
    pub whitelist: AccessListConfig,
    pub blacklist: AccessListConfig,
    pub docker: bool,
    pub interfaces: Vec<String>,
    pub iplists: HashMap<String, crate::IpListConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: String::from("127.0.0.1"),
            port: 8990,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FeaturesConfig {
    pub portforward: bool,
    pub block_badtcp: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AccessListConfig {
    pub enabled: bool,
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            let config = Config::default();
            config.save(path)?;
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)
    }

    pub fn update_from_cli(&mut self, cli_config: CliConfig) {
        if cli_config.host.is_some() {
            self.server.host = cli_config.host.unwrap();
        }
        if cli_config.port.is_some() {
            self.server.port = cli_config.port.unwrap();
        }
        if cli_config.portforward.is_some() {
            self.features.portforward = cli_config.portforward.unwrap();
        }
        if cli_config.block_badtcp.is_some() {
            self.features.block_badtcp = cli_config.block_badtcp.unwrap();
        }
        if cli_config.docker.is_some() {
            self.docker = cli_config.docker.unwrap();
        }
        if cli_config.interfaces.is_some() {
            self.interfaces = cli_config.interfaces.unwrap();
        }
    }

    // pub fn get_iplist_config(&self, name: &str) -> Option<&crate::IpListConfig> {
    //     self.iplists.get(name)
    // }
}

pub struct CliConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub portforward: Option<bool>,
    pub block_badtcp: Option<bool>,
    pub docker: Option<bool>,
    pub interfaces: Option<Vec<String>>,
}
