use crate::error::{Error, Result};
use async_trait::async_trait;
use reqwest::Client;
use super::iplist::IpList;

pub struct CloudflareList {
    name: String,
}

impl CloudflareList {
    pub fn new() -> Self {
        CloudflareList {
            name: String::from("cloudflare"),
        }
    }
}

#[async_trait]
impl IpList for CloudflareList {
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
            .get("https://www.cloudflare.com/ips-v4")
            .send()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to fetch Cloudflare IPv4: {}", e)))?
            .text()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to read Cloudflare IPv4: {}", e)))
    }

    async fn fetch_ipv6(&self, client: &Client) -> Result<String> {
        client
            .get("https://www.cloudflare.com/ips-v6")
            .send()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to fetch Cloudflare IPv6: {}", e)))?
            .text()
            .await
            .map_err(|e| Error::CommandFailed(format!("Failed to read Cloudflare IPv6: {}", e)))
    }
} 