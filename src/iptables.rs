use log::info;

use crate::cmd::CmdBuilder;
use crate::config::Config;
use crate::error::Result;
use crate::ipset::IpsetController;
use crate::rules::{Rule, RuleParser};

pub struct IptablesController {
    cmd_v4: CmdBuilder,
    cmd_v6: CmdBuilder,
}

impl IptablesController {
    pub fn new(dry_run: bool) -> Self {
        IptablesController {
            cmd_v4: CmdBuilder::new("iptables").with_dry_run(dry_run),
            cmd_v6: CmdBuilder::new("ip6tables").with_dry_run(dry_run),
        }
    }

    #[inline]
    fn execute_v4(&self, args: &[&str]) -> Result<String> {
        self.cmd_v4.clone().args(args).execute()
    }

    #[inline]
    fn execute_v6(&self, args: &[&str]) -> Result<String> {
        self.cmd_v6.clone().args(args).execute()
    }

    #[inline]
    fn execute_both(&self, args: &[&str]) -> Result<()> {
        // Execute for IPv4
        self.execute_v4(args)?;
        // Execute for IPv6
        self.execute_v6(args)?;
        Ok(())
    }

    pub fn init(&self) -> Result<()> {
        // Create and reset main chain ei for both IPv4 and IPv6
        self.create_or_reset_chain("ei")?;

        // Add chain ei to INPUT and FORWARD for both IPv4 and IPv6
        self.add_chain_to_filter("ei")?;

        // Accept loopback traffic
        self.accept_loopback()?;

        Ok(())
    }

    pub fn configure(&self, config: &Config) -> Result<()> {
        // Configure features
        if config.features.portforward {
            self.configure_port_forwarding()?;
        }

        if config.features.block_badtcp {
            self.configure_badtcp()?;
        }

        // Configure Docker blocking
        if config.docker {
            self.configure_docker_blacklist()?;
        }

        // Configure interface blocking
        self.configure_interface_blocking(&config.interfaces)?;

        Ok(())
    }

    // Split configure into smaller, focused methods
    fn configure_port_forwarding(&self) -> Result<()> {
        self.create_or_reset_chain("ei-ports")?;
        self.add_chain_to_chain("ei-ports", "ei")?;
        self.add_ipset_rules_to_ports()
    }

    fn configure_badtcp(&self) -> Result<()> {
        self.create_or_reset_chain("ei-badtcp")?;
        self.add_chain_to_chain("ei-badtcp", "ei")?;
        self.implement_badtcp_rules()
    }

    fn configure_docker_blacklist(&self) -> Result<()> {
        self.create_or_reset_chain("ei-docker")?;
        self.add_chain_to_chain("ei-docker", "DOCKER-USER")?;
        self.implement_docker_blacklist_rules()
    }

    fn configure_interface_blocking(&self, interfaces: &[String]) -> Result<()> {
        for interface in interfaces {
            self.block_interface(interface)?;
        }
        Ok(())
    }

    fn implement_docker_blacklist_rules(&self) -> Result<()> {
        info!("Implementing Docker blacklist rules");
        self.execute_both(&[
            "-A",
            "ei-docker",
            "-m",
            "set",
            "--match-set",
            "ei-blacklist",
            "src",
            "-j",
            "DROP",
        ])
    }

    fn create_or_reset_chain(&self, chain_name: &str) -> Result<()> {
        info!("Creating or resetting chain: {}", chain_name);
        // Try to create new chain (might fail if exists)
        self.execute_both(&["-N", chain_name])?;

        // Flush the chain (remove all rules)
        self.execute_both(&["-F", chain_name])
    }

    fn add_chain_to_filter(&self, chain_name: &str) -> Result<()> {
        info!("Adding chain to INPUT/FOWARD: {}", chain_name);
        self.execute_both(&["-A", "INPUT", "-j", chain_name])?;
        self.execute_both(&["-A", "FORWARD", "-j", chain_name])
    }

    fn add_chain_to_chain(&self, source_chain: &str, target_chain: &str) -> Result<()> {
        info!(
            "Adding chain to chain: {} -> {}",
            source_chain, target_chain
        );
        // First remove any existing references
        self.execute_both(&["-D", target_chain, "-j", source_chain])?;

        // Then add the chain reference
        self.execute_both(&["-A", target_chain, "-j", source_chain])
    }

    fn block_interface(&self, interface: &str) -> Result<()> {
        info!("Blocking interface: {}", interface);
        self.execute_both(&["-A", "ei", "-i", interface, "-j", "DROP"])
    }

    fn accept_loopback(&self) -> Result<()> {
        info!("Accepting loopback traffic");
        self.execute_both(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
        self.execute_both(&["-A", "FORWARD", "-i", "lo", "-j", "ACCEPT"])
    }

    fn add_ipset_rules_to_ports(&self) -> Result<()> {
        info!("Adding ipset rules to ports");
        // Add TCP rules for both IPv4 and IPv6
        self.execute_both(&[
            "-A",
            "ei-ports",
            "-p",
            "tcp",
            "-m",
            "set",
            "--match-set",
            "ei-allowed-tcp-ports",
            "dst",
            "-j",
            "ACCEPT",
        ])?;

        // Add UDP rules for both IPv4 and IPv6
        self.execute_both(&[
            "-A",
            "ei-ports",
            "-p",
            "udp",
            "-m",
            "set",
            "--match-set",
            "ei-allowed-udp-ports",
            "dst",
            "-j",
            "ACCEPT",
        ])?;

        Ok(())
    }

    fn implement_badtcp_rules(&self) -> Result<()> {
        info!("Implementing badtcp rules");
        self.execute_both(&[
            "-A",
            "ei",
            "-p",
            "tcp",
            "--tcp-flags",
            "ALL",
            "NONE",
            "-j",
            "DROP",
        ])?;
        todo!("add actual rules here");
    }

    fn add_chain_to_chain_start(&self, source_chain: &str, target_chain: &str) -> Result<()> {
        info!(
            "Adding chain to chain at the beginning: {} -> {}",
            source_chain, target_chain
        );
        // First remove any existing references
        let _ = self.execute_both(&["-D", target_chain, "-j", source_chain]);

        // Then add the chain reference at the beginning
        self.execute_both(&["-I", target_chain, "1", "-j", source_chain])
    }

    pub fn configure_with_rules(
        &self,
        config: &Config,
        rule_parser: &RuleParser,
        ipset: &IpsetController,
    ) -> Result<()> {
        // Configure whitelists first (highest priority)
        self.configure_whitelist_chain(rule_parser, ipset)?;

        // Configure blacklists next
        self.configure_blacklist_chain(rule_parser, ipset)?;

        // Configure services and firewall features
        self.configure(config)?;

        Ok(())
    }

    fn configure_whitelist_chain(
        &self,
        rule_parser: &RuleParser,
        ipset: &IpsetController,
    ) -> Result<()> {
        self.create_or_reset_chain("ei-whitelist")?;
        self.add_chain_to_chain_start("ei-whitelist", "ei")?;

        rule_parser.get_whitelist_rules().iter().for_each(|rule| {
            if let Rule::Port(port) = rule {
                ipset.add_to_whitelist(port.number, port.protocol).unwrap();
            }
        });

        // Add ipset rules
        for set_name in ipset
            .get_whitelist_sets()
            .iter()
            .flat_map(|e| vec![format!("ei-{}-ipv4", e), format!("ei-{}-ipv6", e)])
            .chain([
                "ei-whitelist-tcp".to_string(),
                "ei-whitelist-udp".to_string(),
            ])
        {
            self.execute_both(&[
                "-A",
                "ei-whitelist",
                "-m",
                "set",
                "--match-set",
                &set_name,
                "dst",
                "-j",
                "ACCEPT",
            ])?;
        }

        Ok(())
    }

    fn configure_blacklist_chain(
        &self,
        rule_parser: &RuleParser,
        ipset: &IpsetController,
    ) -> Result<()> {
        self.create_or_reset_chain("ei-blacklist")?;
        self.add_chain_to_chain("ei-blacklist", "ei")?;

        rule_parser.get_blacklist_rules().iter().for_each(|rule| {
            if let Rule::Port(port) = rule {
                ipset.add_to_blacklist(port.number, port.protocol).unwrap();
            }
        });

        // Add ipset rules
        for set_name in ipset
            .get_blacklist_sets()
            .iter()
            .flat_map(|e| {
                [
                    format!("ei-{}-ipv4", e).to_string(),
                    format!("ei-{}-ipv6", e).to_string(),
                ]
            })
            .chain([
                "ei-blacklist-tcp".to_string(),
                "ei-blacklist-udp".to_string(),
            ])
        {
            self.execute_v4(&[
                "-A",
                "ei-blacklist",
                "-m",
                "set",
                "--match-set",
                &set_name,
                "src",
                "-j",
                "DROP",
            ])?;
        }

        Ok(())
    }
}
