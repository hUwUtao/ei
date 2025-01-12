use crate::config::Config;
use crate::error::{Error, Result};
use crate::ipset::IpsetController;
use crate::rules::IpListConfig;
use async_trait::async_trait;
use reqwest::Client;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[async_trait]
pub trait IpList: Send + Sync {
    fn name(&self) -> &str;
    fn ipv4_set_name(&self) -> String;
    fn ipv6_set_name(&self) -> String;
    async fn fetch_ipv4(&self, client: &Client) -> Result<String>;
    async fn fetch_ipv6(&self, client: &Client) -> Result<String>;
}

pub struct ConfigurableIpList {
    name: String,
    config: IpListConfig,
}

impl ConfigurableIpList {
    pub fn new(name: String, config: IpListConfig) -> Self {
        ConfigurableIpList { name, config }
    }
}

#[async_trait]
impl IpList for ConfigurableIpList {
    fn name(&self) -> &str {
        &self.name
    }

    fn ipv4_set_name(&self) -> String {
        format!("ei-{}-ipv4", self.name)
    }

    fn ipv6_set_name(&self) -> String {
        format!("ei-{}-ipv6", self.name)
    }

    async fn fetch_ipv4(&self, client: &Client) -> Result<String> {
        client
            .get(&self.config.urls.ipv4)
            .send()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to fetch IPv4: {}", e)))?
            .text()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to read IPv4: {}", e)))
    }

    async fn fetch_ipv6(&self, client: &Client) -> Result<String> {
        client
            .get(&self.config.urls.ipv6)
            .send()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to fetch IPv6: {}", e)))?
            .text()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to read IPv6: {}", e)))
    }
}

pub struct IpListManager {
    ipset: Arc<RwLock<IpsetController>>,
    lists: Vec<Box<dyn IpList>>,
}

impl IpListManager {
    pub fn new(ipset: Arc<RwLock<IpsetController>>) -> Self {
        IpListManager {
            ipset,
            lists: Vec::new(),
        }
    }

    pub fn load_from_config(&mut self, config: &Config) {
        for (name, list_config) in &config.iplists {
            if list_config.enabled {
                self.add_list(Box::new(ConfigurableIpList::new(
                    name.clone(),
                    list_config.clone(),
                )));
            }
        }
    }

    pub fn add_list(&mut self, list: Box<dyn IpList>) {
        self.lists.push(list);
    }

    pub async fn update_all(&self) -> Result<()> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::CommandFailed(format!("Failed to create HTTP client: {}", e)))?;

        for list in &self.lists {
            self.update_list(&client, list.as_ref()).await?;
        }

        Ok(())
    }

    pub fn register_whitelist_set(&self, name: String) {
        self.ipset.write().unwrap().register_whitelist_set(name);
    }

    pub fn register_blacklist_set(&self, name: String) {
        self.ipset.write().unwrap().register_blacklist_set(name);
    }

    async fn update_list(&self, client: &Client, list: &dyn IpList) -> Result<()> {
        let ipv4_set = list.ipv4_set_name();
        let ipv6_set: String = list.ipv6_set_name();

        // Create/reset IPv4 set
        self.ipset
            .write()
            .unwrap()
            .create_or_reset_ipset(&ipv4_set)?;

        // Create/reset IPv6 set
        self.ipset
            .write()
            .unwrap()
            .create_or_reset_ipset(&ipv6_set)?;

        // Fetch and add IPv4 ranges
        let ipv4_ranges = list.fetch_ipv4(client).await?;
        for ip in ipv4_ranges.lines() {
            if !ip.is_empty() {
                self.ipset.write().unwrap().add_to_set(&ipv4_set, ip)?;
            }
        }

        // Fetch and add IPv6 ranges
        let ipv6_ranges = list.fetch_ipv6(client).await?;
        for ip in ipv6_ranges.lines() {
            if !ip.is_empty() {
                self.ipset.write().unwrap().add_to_set(&ipv6_set, ip)?;
            }
        }

        Ok(())
    }
}
