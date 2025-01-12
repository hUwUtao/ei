use std::collections::HashMap;
use crate::rules::{IpListConfig, Rule, IpListRule};
use super::cloudflare::CloudflareList;
use super::iplist::{IpList, ConfigurableIpList};
use crate::config::Config;

pub struct IpListResolver {
    configs: HashMap<String, IpListConfig>,
    builtin: HashMap<String, Box<dyn Fn() -> Box<dyn IpList> + Send + Sync>>,
}

impl IpListResolver {
    pub fn new() -> Self {
        let mut resolver = IpListResolver {
            configs: HashMap::new(),
            builtin: HashMap::new(),
        };
        
        // Register built-in IP lists
        resolver.register_builtin("cloudflare", || Box::new(CloudflareList::new()));
        
        resolver
    }

    pub fn load_config(&mut self, config: &Config) {
        self.configs = config.iplists.clone();
    }

    pub fn register_builtin<F>(&mut self, name: &str, factory: F)
    where
        F: Fn() -> Box<dyn IpList> + Send + Sync + 'static,
    {
        self.builtin.insert(name.to_string(), Box::new(factory));
    }

    pub fn resolve(&self, rule: &Rule) -> Option<Box<dyn IpList>> {
        match rule {
            Rule::IpList(IpListRule { name, config }) => {
                // First check if it's a built-in list
                if let Some(factory) = self.builtin.get(name) {
                    return Some(factory());
                }

                // Then check if it's a configured list
                if let Some(config) = config.as_ref().or_else(|| self.configs.get(name)) {
                    if config.enabled {
                        return Some(Box::new(ConfigurableIpList::new(
                            name.clone(),
                            config.clone(),
                        )));
                    }
                }

                None
            }
            _ => None,
        }
    }

    pub fn resolve_all(&self, rules: &[Rule]) -> Vec<Box<dyn IpList>> {
        rules
            .iter()
            .filter_map(|rule| self.resolve(rule))
            .collect()
    }
} 