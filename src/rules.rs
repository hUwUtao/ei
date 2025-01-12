use log::error;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize)]
pub enum Rule {
    Port(PortRule),
    IpList(IpListRule),
    IpSet(IpSetRule),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    pub number: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpListRule {
    pub name: String,
    pub config: Option<IpListConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpSetRule {
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
}

impl TryFrom<String> for Protocol {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            _ => Err("Invalid protocol".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpListConfig {
    pub urls: IpListUrls,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpListUrls {
    pub ipv4: String,
    pub ipv6: String,
}

impl FromStr for Rule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            // Parse port rule (e.g., "80/tcp")
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() != 2 {
                return Err(
                    "Invalid port format. Expected: port/protocol (e.g., 80/tcp)".to_string(),
                );
            }

            let port = parts[0].parse::<u16>().map_err(|_| {
                format!(
                    "Invalid port number: '{}'. Port must be a valid number between 0 and 65535.",
                    parts[0]
                )
            })?;
            let protocol = Protocol::from_str(parts[1]).map_err(|_| {
                format!(
                    "Invalid protocol: '{}'. Protocol must be one of 'tcp', 'udp', etc.",
                    parts[1]
                )
            })?;

            Ok(Rule::Port(PortRule {
                number: port,
                protocol,
            }))
        } else if s.starts_with("iplist:") {
            // Parse iplist rule (e.g., "iplist:cloudflare")
            if s.len() <= 7 {
                return Err(
                    "Invalid iplist format. Expected: iplist:<name> (e.g., iplist:cloudflare)"
                        .to_string(),
                );
            }
            Ok(Rule::IpList(IpListRule {
                name: s[7..].to_string(),
                config: None,
            }))
        } else if s.starts_with("ipset:") {
            // Parse ipset rule (e.g., "ipset:xcord")
            if s.len() <= 6 {
                return Err(
                    "Invalid ipset format. Expected: ipset:<name> (e.g., ipset:xcord)".to_string(),
                );
            }
            Ok(Rule::IpSet(IpSetRule {
                name: s[6..].to_string(),
            }))
        } else {
            error!(
                "Invalid rule format: '{}'.\nHint: Valid formats are:\n\
                - Port rule: port/protocol (e.g., 80/tcp)\n\
                - IpList rule: iplist:<name> (e.g., iplist:cloudflare)\n\
                - IpSet rule: ipset:<name> (e.g., ipset:xcord)",
                s
            );
            Err("Invalid rule format".to_string())
        }
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Rule::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            _ => Err("Protocol must be tcp or udp".to_string()),
        }
    }
}

impl ToString for Protocol {
    fn to_string(&self) -> String {
        match self {
            Protocol::TCP => "tcp".to_string(),
            Protocol::UDP => "udp".to_string(),
        }
    }
}

// impl Rule {
//     pub fn parse_many(rules: &[String]) -> Vec<Rule> {
//         rules
//             .iter()
//             .filter_map(|rule| Rule::from_str(rule).ok())
//             .collect()
//     }
// }

#[derive(Debug, Clone)]
pub struct RuleParser {
    whitelist_rules: Vec<Rule>,
    blacklist_rules: Vec<Rule>,
}

impl RuleParser {
    pub fn new() -> Self {
        RuleParser {
            whitelist_rules: Vec::new(),
            blacklist_rules: Vec::new(),
        }
    }

    pub fn parse_config(&mut self, config: &crate::config::Config) {
        if config.whitelist.enabled {
            self.whitelist_rules = config.whitelist.rules.clone();
        }

        if config.blacklist.enabled {
            self.blacklist_rules = config.blacklist.rules.clone();
        }
    }

    pub fn get_whitelist_rules(&self) -> &[Rule] {
        &self.whitelist_rules
    }

    pub fn get_blacklist_rules(&self) -> &[Rule] {
        &self.blacklist_rules
    }

    pub fn get_iplist_rules(&self) -> Vec<Rule> {
        self.whitelist_rules
            .iter()
            .chain(self.blacklist_rules.iter())
            .map(|rule| rule.clone())
            .filter(|rule| matches!(rule, Rule::IpList(_)))
            .collect()
    }

    pub fn get_port_rules(&self) -> Vec<&Rule> {
        self.whitelist_rules
            .iter()
            .chain(self.blacklist_rules.iter())
            .filter(|rule| matches!(rule, Rule::Port(_)))
            .collect()
    }

    // pub fn get_ipset_rules(&self) -> Vec<&Rule> {
    //     self.whitelist_rules
    //         .iter()
    //         .chain(self.blacklist_rules.iter())
    //         .filter(|rule| matches!(rule, Rule::IpSet(_)))
    //         .collect()
    // }
}
