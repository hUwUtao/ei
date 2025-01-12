use log::info;

use crate::cmd::CmdBuilder;
use crate::error::Result;
use crate::rules::{PortRule, Protocol, Rule};
use std::collections::HashSet;

pub struct IpsetController {
    cmd: CmdBuilder,
    whitelist_sets: HashSet<String>,
    blacklist_sets: HashSet<String>,
}

impl IpsetController {
    pub fn new(dry_run: bool) -> Self {
        IpsetController {
            cmd: CmdBuilder::new("ipset").with_dry_run(dry_run),
            whitelist_sets: HashSet::new(),
            blacklist_sets: HashSet::new(),
        }
    }

    pub fn init(&self) -> Result<()> {
        info!("Initializing ipset controller");
        self.create_or_reset_port_set("ei-allowed-tcp-ports")?;
        self.create_or_reset_port_set("ei-allowed-udp-ports")?;
        self.create_or_reset_port_set("ei-whitelist-tcp")?;
        self.create_or_reset_port_set("ei-whitelist-udp")?;
        self.create_or_reset_port_set("ei-blacklist-tcp")?;
        self.create_or_reset_port_set("ei-blacklist-udp")?;
        Ok(())
    }

    pub fn add_to_whitelist(&self, port: u16, protocol: Protocol) -> Result<()> {
        let set_name = match protocol {
            Protocol::TCP => "ei-whitelist-tcp",
            Protocol::UDP => "ei-whitelist-udp",
        };
        self.add_to_set(set_name, &port.to_string())
    }

    pub fn add_to_blacklist(&self, port: u16, protocol: Protocol) -> Result<()> {
        let set_name = match protocol {
            Protocol::TCP => "ei-blacklist-tcp",
            Protocol::UDP => "ei-blacklist-udp",
        };
        self.add_to_set(set_name, &port.to_string())
    }

    pub fn create_or_reset_ipset(&self, set_name: &str) -> Result<()> {
        let _ = self.execute(&["destroy", set_name]);
        self.execute(&[
            "create", set_name, "hash:ip", "family", "inet", "maxelem", "65536",
        ])?;
        Ok(())
    }

    pub fn register_whitelist_set(&mut self, name: String) {
        info!("Registering whitelist set: {}", name);
        self.whitelist_sets.insert(name);
    }

    pub fn register_blacklist_set(&mut self, name: String) {
        info!("Registering blacklist set: {}", name);
        self.blacklist_sets.insert(name);
    }

    pub fn get_whitelist_sets(&self) -> &HashSet<String> {
        &self.whitelist_sets
    }

    pub fn get_blacklist_sets(&self) -> &HashSet<String> {
        &self.blacklist_sets
    }

    pub fn configure_port_rules(&self, rules: &[&Rule]) -> Result<()> {
        info!("Configuring port rules: {:?}", rules);
        for rule in rules {
            if let Rule::Port(PortRule { number, protocol }) = rule {
                let set_name = match protocol {
                    Protocol::TCP => "ei-allowed-tcp-ports",
                    Protocol::UDP => "ei-allowed-udp-ports",
                };
                self.add_to_set(set_name, &number.to_string())?;
            }
        }
        Ok(())
    }

    fn execute(&self, args: &[&str]) -> Result<String> {
        let mut cmd = self.cmd.clone();
        cmd.args(args).execute()
    }

    fn create_or_reset_port_set(&self, set_name: &str) -> Result<()> {
        let _ = self.execute(&["destroy", set_name]);
        self.execute(&["create", set_name, "bitmap:port", "range", "1-65535"])?;
        Ok(())
    }

    pub fn add_to_set(&self, set_name: &str, value: &str) -> Result<()> {
        self.execute(&["add", set_name, value])?;
        Ok(())
    }

    pub fn list_ports(&self) -> Result<Vec<(u16, Protocol)>> {
        let mut ports = Vec::new();

        if let Ok(output) = self.execute(&["list", "ei-allowed-tcp-ports"]) {
            ports.extend(
                Self::parse_ipset_list(&output)
                    .into_iter()
                    .map(|port| (port, Protocol::TCP)),
            );
        }

        if let Ok(output) = self.execute(&["list", "ei-allowed-udp-ports"]) {
            ports.extend(
                Self::parse_ipset_list(&output)
                    .into_iter()
                    .map(|port| (port, Protocol::UDP)),
            );
        }

        ports.sort_by_key(|(port, _)| *port);
        Ok(ports)
    }

    fn parse_ipset_list(output: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        let mut in_members_section = false;

        for line in output.lines() {
            if line == "Members:" {
                in_members_section = true;
                continue;
            }

            if in_members_section {
                if let Ok(port) = line.trim().parse::<u16>() {
                    ports.push(port);
                }
            }
        }

        ports.sort_unstable();
        ports
    }

    pub fn add_port(&self, port: u16, protocol: Protocol) -> Result<()> {
        let set_name = match protocol {
            Protocol::TCP => "ei-allowed-tcp-ports",
            Protocol::UDP => "ei-allowed-udp-ports",
        };
        self.add_to_set(set_name, &port.to_string())
    }

    pub fn remove_port(&self, port: u16, protocol: Protocol) -> Result<()> {
        let set_name = match protocol {
            Protocol::TCP => "ei-allowed-tcp-ports",
            Protocol::UDP => "ei-allowed-udp-ports",
        };
        self.execute(&["del", set_name, &port.to_string()])?;
        Ok(())
    }
}
