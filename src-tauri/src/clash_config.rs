//! Clash configuration structure and YAML generator
//! Optimized for mihomo (Clash Meta) kernel

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::ini_parser::{to_clash_proxy_groups, to_clash_rules, ParsedIniConfig};
use crate::node::Node;

/// Complete Clash configuration (mihomo compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashConfig {
    /// Mixed port for HTTP/SOCKS proxy
    #[serde(rename = "mixed-port")]
    pub mixed_port: u16,

    /// Allow LAN connections
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,

    /// Bind address
    #[serde(rename = "bind-address", skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,

    /// Proxy mode: rule, global, direct
    pub mode: String,

    /// Log level: silent, error, warning, info, debug
    #[serde(rename = "log-level")]
    pub log_level: String,

    /// IPv6 support
    pub ipv6: bool,

    /// Unified delay calculation (mihomo feature)
    #[serde(rename = "unified-delay")]
    pub unified_delay: bool,

    /// TCP concurrent connections (mihomo feature)
    #[serde(rename = "tcp-concurrent")]
    pub tcp_concurrent: bool,

    /// Global client fingerprint for TLS (critical for Reality/VLESS)
    /// This sets default uTLS fingerprint for all proxies
    #[serde(
        rename = "global-client-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub global_client_fingerprint: Option<String>,

    /// Process matching mode
    #[serde(rename = "find-process-mode", skip_serializing_if = "Option::is_none")]
    pub find_process_mode: Option<String>,

    /// External controller for API
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_controller: Option<String>,

    /// External UI path
    #[serde(rename = "external-ui", skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<String>,

    /// Secret for API access
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Geodata mode (standard or memconservative)
    #[serde(rename = "geodata-mode", skip_serializing_if = "Option::is_none")]
    pub geodata_mode: Option<bool>,

    /// GeoIP/GeoSite auto update interval (hours)
    #[serde(rename = "geo-auto-update", skip_serializing_if = "Option::is_none")]
    pub geo_auto_update: Option<bool>,

    /// GeoIP/GeoSite update interval
    #[serde(
        rename = "geo-update-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub geo_update_interval: Option<u32>,

    /// Profile settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileConfig>,

    /// Sniffer settings (for protocol detection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffer: Option<SnifferConfig>,

    /// DNS settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// Proxy nodes
    pub proxies: Vec<serde_yaml::Value>,

    /// Proxy groups
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<serde_yaml::Value>,

    /// Routing rules
    pub rules: Vec<String>,

    /// Rule providers (remote ruleset URLs from INI config)
    #[serde(rename = "rule-providers", skip_serializing_if = "Vec::is_empty")]
    pub rule_providers: Vec<RuleProvider>,
}

/// Rule provider for remote rulesets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProvider {
    pub name: String,
    pub url: String,
    pub target: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<IndexMap<String, String>>,
    #[serde(rename = "size-limit", skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u32>,
    pub interval: u32,
}

#[derive(Debug, Clone, Default)]
pub struct RuleProviderOptions {
    pub proxy: Option<String>,
    pub header: Option<IndexMap<String, String>>,
    pub size_limit: Option<u32>,
    pub path_omit: bool,
    pub path_template: Option<String>,
}

/// Profile configuration for storing state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(rename = "store-selected")]
    pub store_selected: bool,
    #[serde(rename = "store-fake-ip")]
    pub store_fake_ip: bool,
}

/// Sniffer configuration for protocol detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnifferConfig {
    pub enable: bool,
    #[serde(rename = "force-dns-mapping")]
    pub force_dns_mapping: bool,
    #[serde(rename = "parse-pure-ip")]
    pub parse_pure_ip: bool,
    #[serde(rename = "override-destination")]
    pub override_destination: bool,
    pub sniff: SniffProtocols,
    #[serde(rename = "skip-domain", skip_serializing_if = "Option::is_none")]
    pub skip_domain: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniffProtocols {
    #[serde(rename = "HTTP")]
    pub http: SniffProtocolConfig,
    #[serde(rename = "TLS")]
    pub tls: SniffProtocolConfig,
    #[serde(rename = "QUIC")]
    pub quic: SniffProtocolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniffProtocolConfig {
    pub ports: Vec<String>,
    #[serde(
        rename = "override-destination",
        skip_serializing_if = "Option::is_none"
    )]
    pub override_destination: Option<bool>,
}

/// DNS configuration (mihomo enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enable: bool,
    pub listen: String,
    pub ipv6: bool,
    #[serde(rename = "prefer-h3")]
    pub prefer_h3: bool,
    #[serde(rename = "enhanced-mode")]
    pub enhanced_mode: String,
    #[serde(rename = "fake-ip-range")]
    pub fake_ip_range: String,
    #[serde(rename = "fake-ip-filter", skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter: Option<Vec<String>>,
    #[serde(rename = "default-nameserver")]
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    #[serde(
        rename = "proxy-server-nameserver",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy_server_nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Vec<String>>,
    #[serde(rename = "fallback-filter", skip_serializing_if = "Option::is_none")]
    pub fallback_filter: Option<FallbackFilter>,
    #[serde(rename = "nameserver-policy", skip_serializing_if = "Option::is_none")]
    pub nameserver_policy: Option<IndexMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackFilter {
    pub geoip: bool,
    #[serde(rename = "geoip-code")]
    pub geoip_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite: Option<Vec<String>>,
    pub ipcidr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
}

impl Default for ClashConfig {
    fn default() -> Self {
        Self {
            mixed_port: 7890,
            allow_lan: true,
            bind_address: None,
            mode: "rule".to_string(),
            log_level: "info".to_string(),
            ipv6: false,
            unified_delay: true,
            tcp_concurrent: true,
            // Critical: Set global fingerprint for all TLS connections
            global_client_fingerprint: Some("chrome".to_string()),
            find_process_mode: None,
            external_controller: Some("127.0.0.1:9090".to_string()),
            external_ui: None,
            secret: None,
            // geodata-mode false = use mmdb (built-in, no extra files needed)
            // geodata-mode true = requires geoip.dat/geosite.dat files
            geodata_mode: None,
            geo_auto_update: None,
            geo_update_interval: None,
            profile: Some(ProfileConfig {
                store_selected: true,
                store_fake_ip: true,
            }),
            sniffer: Some(SnifferConfig::default()),
            dns: Some(DnsConfig::default()),
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            rules: Vec::new(),
            rule_providers: Vec::new(),
        }
    }
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            enable: true,
            force_dns_mapping: true,
            parse_pure_ip: true,
            override_destination: false,
            sniff: SniffProtocols {
                http: SniffProtocolConfig {
                    ports: vec!["80".to_string(), "8080-8880".to_string()],
                    override_destination: Some(true),
                },
                tls: SniffProtocolConfig {
                    ports: vec!["443".to_string(), "8443".to_string()],
                    override_destination: None,
                },
                quic: SniffProtocolConfig {
                    ports: vec!["443".to_string(), "8443".to_string()],
                    override_destination: None,
                },
            },
            skip_domain: Some(vec![
                "Mijia Cloud".to_string(),
                "+.push.apple.com".to_string(),
            ]),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            listen: "0.0.0.0:1053".to_string(),
            ipv6: false,
            prefer_h3: false,
            enhanced_mode: "fake-ip".to_string(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: Some(vec![
                "*.lan".to_string(),
                "*.local".to_string(),
                "+.msftconnecttest.com".to_string(),
                "+.msftncsi.com".to_string(),
            ]),
            default_nameserver: vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()],
            nameserver: vec![
                "223.5.5.5".to_string(),
                "119.29.29.29".to_string(),
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
            ],
            proxy_server_nameserver: Some(vec![
                "223.5.5.5".to_string(),
                "119.29.29.29".to_string(),
            ]),
            fallback: Some(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]),
            fallback_filter: None,
            nameserver_policy: None,
        }
    }
}

/// Builder for assembling Clash config
pub struct ClashConfigBuilder {
    config: ClashConfig,
    enable_tun: bool,
    /// Global UDP switch for all nodes
    enable_udp: bool,
    /// Global TCP Fast Open switch
    enable_tfo: bool,
    /// Global skip-cert-verify switch
    skip_cert_verify: bool,
    rule_provider_options: RuleProviderOptions,
}

impl ClashConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: ClashConfig::default(),
            enable_tun: false,
            enable_udp: true,
            enable_tfo: false,
            skip_cert_verify: false,
            rule_provider_options: RuleProviderOptions::default(),
        }
    }

    /// Enable TUN mode for system-wide proxy
    pub fn with_tun(mut self) -> Self {
        self.enable_tun = true;
        self
    }

    /// Set global options for all nodes (UDP, TFO, skip-cert-verify)
    pub fn with_global_options(
        mut self,
        enable_udp: bool,
        enable_tfo: bool,
        skip_cert_verify: bool,
    ) -> Self {
        self.enable_udp = enable_udp;
        self.enable_tfo = enable_tfo;
        self.skip_cert_verify = skip_cert_verify;
        self
    }

    /// Set basic proxy settings
    pub fn with_basic_settings(mut self, mixed_port: u16, allow_lan: bool) -> Self {
        self.config.mixed_port = mixed_port;
        self.config.allow_lan = allow_lan;
        self
    }

    /// Set API settings for external controller
    pub fn with_api_settings(
        mut self,
        external_controller: String,
        secret: Option<String>,
    ) -> Self {
        self.config.external_controller = Some(external_controller);
        self.config.secret = secret;
        self
    }

    /// Set rule-provider download options
    pub fn with_rule_provider_options(mut self, options: RuleProviderOptions) -> Self {
        self.rule_provider_options = options;
        self
    }

    /// Add proxy nodes with global options applied
    pub fn with_nodes(mut self, nodes: &[Node]) -> Self {
        self.config.proxies = nodes
            .iter()
            .map(|n| {
                let mut map = n.to_clash_proxy();
                // Apply global options
                if self.enable_udp {
                    map.insert("udp".to_string(), serde_yaml::Value::Bool(true));
                }
                if self.enable_tfo {
                    map.insert("tfo".to_string(), serde_yaml::Value::Bool(true));
                }
                if self.skip_cert_verify {
                    map.insert(
                        "skip-cert-verify".to_string(),
                        serde_yaml::Value::Bool(true),
                    );
                }
                match serde_yaml::to_value(map) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Warning: Failed to serialize node '{}': {}", n.name(), e);
                        serde_yaml::Value::Null
                    }
                }
            })
            .collect();
        self
    }

    /// Add proxy groups from parsed INI config
    pub fn with_ini_config(mut self, ini_config: &ParsedIniConfig, nodes: &[Node]) -> Self {
        // Convert proxy groups
        let groups = to_clash_proxy_groups(&ini_config.proxy_groups, nodes);
        self.config.proxy_groups = groups
            .into_iter()
            .map(|g| serde_yaml::to_value(g).unwrap_or(serde_yaml::Value::Null))
            .collect();

        // Convert inline rules
        let mut rules = to_clash_rules(&ini_config.rules);

        // Convert remote rulesets to rule-providers + RULE-SET rules
        let mut rule_providers = Vec::new();
        let mut ruleset_rules = Vec::new();

        for (idx, (target, url)) in ini_config.ruleset_urls.iter().enumerate() {
            // Handle explicit behavior prefixes from subconverter format
            // e.g., "clash-domain:url", "clash-ipcidr:url", "clash-classic:url"
            let (behavior, clean_url) = if let Some(rest) = url.strip_prefix("clash-domain:") {
                ("domain", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("clash-ipcidr:") {
                ("ipcidr", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("clash-classic:") {
                ("classical", rest.to_string())
            } else {
                ("classical", url.clone())
            };

            // Derive provider name from URL
            let provider_name = derive_provider_name(&clean_url, idx);

            let format = infer_rule_provider_format(&clean_url).map(|s| s.to_string());
            let path = if self.rule_provider_options.path_omit {
                None
            } else {
                Some(rule_provider_path(
                    &provider_name,
                    format.as_deref(),
                    self.rule_provider_options.path_template.as_deref(),
                ))
            };

            rule_providers.push(RuleProvider {
                name: provider_name.clone(),
                url: clean_url.clone(),
                target: target.clone(),
                provider_type: "http".to_string(),
                behavior: behavior.to_string(),
                format,
                path,
                proxy: self.rule_provider_options.proxy.clone(),
                header: self.rule_provider_options.header.clone(),
                size_limit: self.rule_provider_options.size_limit,
                interval: 86400,
            });

            let no_resolve = behavior == "ipcidr";
            if no_resolve {
                ruleset_rules.push(format!("RULE-SET,{},{},no-resolve", provider_name, target));
            } else {
                ruleset_rules.push(format!("RULE-SET,{},{}", provider_name, target));
            }
        }

        // Insert RULE-SET rules before inline rules (which typically end with MATCH)
        ruleset_rules.append(&mut rules);
        self.config.rules = ruleset_rules;
        self.config.rule_providers = rule_providers;

        self
    }

    /// Add default proxy groups if no INI config
    pub fn with_default_groups(mut self, nodes: &[Node]) -> Self {
        let node_names: Vec<String> = nodes.iter().map(|n| n.name().to_string()).collect();

        // Create default groups
        let mut groups = Vec::new();

        // Proxy group (select all nodes)
        let mut proxy_group: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        proxy_group.insert(
            "name".into(),
            serde_yaml::Value::String("🔰 节点选择".into()),
        );
        proxy_group.insert("type".into(), serde_yaml::Value::String("select".into()));
        let mut proxies: Vec<serde_yaml::Value> = vec![
            serde_yaml::Value::String("♻️ 自动选择".into()),
            serde_yaml::Value::String("🎯 全球直连".into()),
        ];
        for name in &node_names {
            proxies.push(serde_yaml::Value::String(name.clone()));
        }
        proxy_group.insert("proxies".into(), serde_yaml::Value::Sequence(proxies));
        groups.push(serde_yaml::to_value(proxy_group).unwrap_or(serde_yaml::Value::Null));

        // Auto group (url-test)
        let mut auto_group: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        auto_group.insert(
            "name".into(),
            serde_yaml::Value::String("♻️ 自动选择".into()),
        );
        auto_group.insert("type".into(), serde_yaml::Value::String("url-test".into()));
        auto_group.insert(
            "url".into(),
            serde_yaml::Value::String("http://www.gstatic.com/generate_204".into()),
        );
        auto_group.insert("interval".into(), serde_yaml::Value::Number(300.into()));
        auto_group.insert(
            "proxies".into(),
            serde_yaml::Value::Sequence(
                node_names
                    .iter()
                    .map(|n| serde_yaml::Value::String(n.clone()))
                    .collect(),
            ),
        );
        groups.push(serde_yaml::to_value(auto_group).unwrap_or(serde_yaml::Value::Null));

        // Direct group
        let mut direct_group: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        direct_group.insert(
            "name".into(),
            serde_yaml::Value::String("🎯 全球直连".into()),
        );
        direct_group.insert("type".into(), serde_yaml::Value::String("select".into()));
        direct_group.insert(
            "proxies".into(),
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("DIRECT".into())]),
        );
        groups.push(serde_yaml::to_value(direct_group).unwrap_or(serde_yaml::Value::Null));

        // Reject group
        let mut reject_group: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        reject_group.insert(
            "name".into(),
            serde_yaml::Value::String("🛑 全球拦截".into()),
        );
        reject_group.insert("type".into(), serde_yaml::Value::String("select".into()));
        reject_group.insert(
            "proxies".into(),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("REJECT".into()),
                serde_yaml::Value::String("DIRECT".into()),
            ]),
        );
        groups.push(serde_yaml::to_value(reject_group).unwrap_or(serde_yaml::Value::Null));

        // Fallback group
        let mut fish_group: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        fish_group.insert(
            "name".into(),
            serde_yaml::Value::String("🐟 漏网之鱼".into()),
        );
        fish_group.insert("type".into(), serde_yaml::Value::String("select".into()));
        let fish_proxies: Vec<serde_yaml::Value> = vec![
            serde_yaml::Value::String("🔰 节点选择".into()),
            serde_yaml::Value::String("🎯 全球直连".into()),
            serde_yaml::Value::String("♻️ 自动选择".into()),
        ];
        fish_group.insert("proxies".into(), serde_yaml::Value::Sequence(fish_proxies));
        groups.push(serde_yaml::to_value(fish_group).unwrap_or(serde_yaml::Value::Null));

        self.config.proxy_groups = groups;
        self
    }

    /// Add default rules if no INI config
    pub fn with_default_rules(mut self) -> Self {
        self.config.rules = vec![
            "DOMAIN-SUFFIX,local,🎯 全球直连".into(),
            "IP-CIDR,192.168.0.0/16,🎯 全球直连,no-resolve".into(),
            "IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve".into(),
            "IP-CIDR,172.16.0.0/12,🎯 全球直连,no-resolve".into(),
            "IP-CIDR,127.0.0.0/8,🎯 全球直连,no-resolve".into(),
            "GEOIP,CN,🎯 全球直连".into(),
            "MATCH,🐟 漏网之鱼".into(),
        ];
        self
    }

    /// Set proxy groups directly
    pub fn with_proxy_groups(mut self, groups: Vec<IndexMap<String, serde_yaml::Value>>) -> Self {
        self.config.proxy_groups = groups
            .into_iter()
            .map(|g| serde_yaml::to_value(g).unwrap_or(serde_yaml::Value::Null))
            .collect();
        self
    }

    /// Set rules directly
    pub fn with_rules(mut self, rules: Vec<String>) -> Self {
        self.config.rules = rules;
        self
    }

    /// Disable DNS config
    pub fn without_dns(mut self) -> Self {
        self.config.dns = None;
        self
    }

    /// Build the final config
    pub fn build(self) -> ClashConfig {
        self.config
    }

    /// Build and serialize to YAML string
    /// Generates a simple, compatible config that works with all Mihomo/Clash Meta versions
    pub fn build_yaml(self) -> Result<String, serde_yaml::Error> {
        let enable_tun = self.enable_tun;
        let config = self.build();

        let mut output = String::new();

        // Header comment
        output.push_str("# Clash Meta Configuration\n");
        output.push_str("# Generated by LocalSub\n\n");

        // Basic settings
        output.push_str("# 基础设置\n");
        output.push_str(&format!("mixed-port: {}\n", config.mixed_port));
        output.push_str(&format!("allow-lan: {}\n", config.allow_lan));
        output.push_str(&format!("mode: {}\n", config.mode));
        output.push_str(&format!("log-level: {}\n", config.log_level));
        output.push_str(&format!("ipv6: {}\n", config.ipv6));
        output.push_str(&format!("unified-delay: {}\n", config.unified_delay));
        output.push_str(&format!("tcp-concurrent: {}\n", config.tcp_concurrent));
        if let Some(fpm) = &config.find_process_mode {
            output.push_str(&format!("find-process-mode: {}\n", fpm));
        }
        if let Some(ec) = &config.external_controller {
            let v = serde_yaml::Value::String(ec.clone());
            output.push_str(&format!(
                "external-controller: {}\n",
                format_yaml_value_simple(&v)
            ));
        }
        if let Some(secret) = &config.secret {
            let v = serde_yaml::Value::String(secret.clone());
            output.push_str(&format!("secret: {}\n", format_yaml_value_simple(&v)));
        }
        output.push('\n');

        // TUN settings (optional)
        if enable_tun {
            output.push_str("# TUN 模式 (系统代理)\n");
            output.push_str("tun:\n");
            output.push_str("  enable: true\n");
            output.push_str("  stack: mixed\n");
            output.push_str("  dns-hijack:\n");
            output.push_str("    - any:53\n");
            output.push_str("    - tcp://any:53\n");
            output.push_str("  auto-route: true\n");
            output.push_str("  auto-redirect: true\n");
            output.push_str("  auto-detect-interface: true\n");
            output.push('\n');
        }

        // Profile settings
        if let Some(profile) = &config.profile {
            output.push_str("# 缓存设置\n");
            output.push_str("profile:\n");
            output.push_str(&format!("  store-selected: {}\n", profile.store_selected));
            output.push_str(&format!("  store-fake-ip: {}\n", profile.store_fake_ip));
            output.push('\n');
        }

        // Sniffer settings
        if let Some(sniffer) = &config.sniffer {
            output.push_str("# 域名嗅探\n");
            output.push_str("sniffer:\n");
            output.push_str(&format!("  enable: {}\n", sniffer.enable));
            output.push_str(&format!(
                "  force-dns-mapping: {}\n",
                sniffer.force_dns_mapping
            ));
            output.push_str(&format!("  parse-pure-ip: {}\n", sniffer.parse_pure_ip));
            output.push_str(&format!(
                "  override-destination: {}\n",
                sniffer.override_destination
            ));
            output.push_str("  sniff:\n");
            output.push_str("    HTTP:\n");
            output.push_str(&format!(
                "      ports: [{}]\n",
                sniffer
                    .sniff
                    .http
                    .ports
                    .iter()
                    .map(|p| format!("\"{}\"", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            if let Some(od) = sniffer.sniff.http.override_destination {
                output.push_str(&format!("      override-destination: {}\n", od));
            }
            output.push_str("    TLS:\n");
            output.push_str(&format!(
                "      ports: [{}]\n",
                sniffer
                    .sniff
                    .tls
                    .ports
                    .iter()
                    .map(|p| format!("\"{}\"", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            if let Some(od) = sniffer.sniff.tls.override_destination {
                output.push_str(&format!("      override-destination: {}\n", od));
            }
            output.push_str("    QUIC:\n");
            output.push_str(&format!(
                "      ports: [{}]\n",
                sniffer
                    .sniff
                    .quic
                    .ports
                    .iter()
                    .map(|p| format!("\"{}\"", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            if let Some(od) = sniffer.sniff.quic.override_destination {
                output.push_str(&format!("      override-destination: {}\n", od));
            }
            if let Some(skip) = &sniffer.skip_domain {
                output.push_str("  skip-domain:\n");
                for d in skip {
                    output.push_str(&format!("    - \"{}\"\n", d));
                }
            }
            output.push('\n');
        }

        // DNS settings
        if let Some(dns) = &config.dns {
            output.push_str("# DNS 设置\n");
            output.push_str("dns:\n");
            output.push_str(&format!("  enable: {}\n", dns.enable));
            output.push_str(&format!("  listen: {}\n", dns.listen));
            output.push_str(&format!("  ipv6: {}\n", dns.ipv6));
            output.push_str(&format!("  prefer-h3: {}\n", dns.prefer_h3));
            output.push_str(&format!("  enhanced-mode: {}\n", dns.enhanced_mode));
            output.push_str(&format!("  fake-ip-range: {}\n", dns.fake_ip_range));
            if let Some(filter) = &dns.fake_ip_filter {
                output.push_str("  fake-ip-filter:\n");
                for f in filter {
                    output.push_str(&format!("    - \"{}\"\n", f));
                }
            }
            output.push_str("  default-nameserver:\n");
            for ns in &dns.default_nameserver {
                output.push_str(&format!("    - {}\n", ns));
            }
            output.push_str("  nameserver:\n");
            for ns in &dns.nameserver {
                output.push_str(&format!("    - {}\n", ns));
            }
            if let Some(proxy_server_nameserver) = &dns.proxy_server_nameserver {
                output.push_str("  proxy-server-nameserver:\n");
                for ns in proxy_server_nameserver {
                    output.push_str(&format!("    - {}\n", ns));
                }
            }
            if let Some(fallback) = &dns.fallback {
                output.push_str("  fallback:\n");
                for ns in fallback {
                    output.push_str(&format!("    - {}\n", ns));
                }
            }
            if let Some(ff) = &dns.fallback_filter {
                output.push_str("  fallback-filter:\n");
                output.push_str(&format!("    geoip: {}\n", ff.geoip));
                output.push_str(&format!("    geoip-code: {}\n", ff.geoip_code));
                if let Some(geosite) = &ff.geosite {
                    output.push_str("    geosite:\n");
                    for gs in geosite {
                        output.push_str(&format!("      - {}\n", gs));
                    }
                }
                output.push_str("    ipcidr:\n");
                for cidr in &ff.ipcidr {
                    output.push_str(&format!("      - {}\n", cidr));
                }
                if let Some(domains) = &ff.domain {
                    output.push_str("    domain:\n");
                    for d in domains {
                        output.push_str(&format!("      - \"{}\"\n", d));
                    }
                }
            }
            if let Some(policy) = &dns.nameserver_policy {
                output.push_str("  nameserver-policy:\n");
                for (domain, servers) in policy {
                    output.push_str(&format!("    \"{}\":\n", domain));
                    for s in servers {
                        output.push_str(&format!("      - {}\n", s));
                    }
                }
            }
            output.push('\n');
        }

        // Proxies section
        output.push_str("# 代理节点\n");
        output.push_str("proxies:\n");
        for proxy in &config.proxies {
            output.push_str(&format_proxy_yaml(proxy)?);
        }
        output.push('\n');

        // Proxy groups
        output.push_str("# 策略组\n");
        output.push_str("proxy-groups:\n");
        for group in &config.proxy_groups {
            output.push_str(&format_group_yaml(group)?);
        }
        output.push('\n');

        // Rules - if rule-providers exist, output them but also add fallback inline rules
        if !config.rule_providers.is_empty() {
            output.push_str("# 规则集\n");
            output.push_str("rule-providers:\n");
            for rp in &config.rule_providers {
                output.push_str(&format!("  {}:\n", rp.name));
                output.push_str(&format!("    type: {}\n", rp.provider_type));
                output.push_str(&format!("    behavior: {}\n", rp.behavior));
                output.push_str(&format!("    url: \"{}\"\n", rp.url));
                if let Some(fmt) = &rp.format {
                    output.push_str(&format!("    format: {}\n", fmt));
                }
                if let Some(path) = &rp.path {
                    output.push_str(&format!("    path: \"{}\"\n", path));
                }
                if let Some(proxy) = &rp.proxy {
                    let v = serde_yaml::Value::String(proxy.clone());
                    output.push_str(&format!("    proxy: {}\n", format_yaml_value_simple(&v)));
                }
                if let Some(header) = &rp.header {
                    if !header.is_empty() {
                        output.push_str("    header:\n");
                        for (k, v) in header {
                            let vv = serde_yaml::Value::String(v.clone());
                            output.push_str(&format!(
                                "      {}: {}\n",
                                k,
                                format_yaml_value_simple(&vv)
                            ));
                        }
                    }
                }
                if let Some(size_limit) = rp.size_limit {
                    output.push_str(&format!("    size-limit: {}\n", size_limit));
                }
                output.push_str(&format!("    interval: {}\n", rp.interval));
            }
            output.push('\n');
        }

        // Rules
        output.push_str("# 分流规则\n");
        output.push_str("rules:\n");
        for rule in &config.rules {
            output.push_str(&format!("  - {}\n", rule));
        }

        // Validate: parse the generated YAML back to catch any format errors
        let _: serde_yaml::Value = serde_yaml::from_str(&output)?;

        Ok(output)
    }
}

/// Derive a rule-provider name from a URL
fn derive_provider_name(url: &str, index: usize) -> String {
    // Try to extract a meaningful name from the URL filename
    if let Some(filename) = url.rsplit('/').next() {
        let name = filename
            .trim_end_matches(".list")
            .trim_end_matches(".yaml")
            .trim_end_matches(".txt")
            .trim_end_matches(".mrs");
        if !name.is_empty() && name.len() <= 50 {
            // Sanitize: only keep alphanumeric, hyphen, underscore
            let sanitized: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            return sanitized;
        }
    }
    format!("provider-{}", index)
}

/// Infer rule-provider format from URL extension.
fn infer_rule_provider_format(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    if lower.ends_with(".mrs") {
        Some("mrs")
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        Some("yaml")
    } else if lower.ends_with(".list") || lower.ends_with(".txt") {
        Some("text")
    } else {
        None
    }
}

/// Build a ruleset path matching the inferred format or template.
fn rule_provider_path(name: &str, format: Option<&str>, template: Option<&str>) -> String {
    let ext = match format {
        Some("mrs") => "mrs",
        Some("text") => "txt",
        _ => "yaml",
    };
    if let Some(tpl) = template {
        apply_rule_provider_path_template(tpl, name, ext)
    } else {
        format!("./ruleset/{}.{}", name, ext)
    }
}

fn apply_rule_provider_path_template(template: &str, name: &str, ext: &str) -> String {
    if template.contains("{name}") || template.contains("{ext}") {
        return template.replace("{name}", name).replace("{ext}", ext);
    }
    let mut base = template.to_string();
    if !base.ends_with('/') && !base.ends_with('\\') {
        base.push('/');
    }
    format!("{}{}.{}", base, name, ext)
}

/// Format a single proxy node to YAML with proper indentation and quoting
fn format_proxy_yaml(proxy: &serde_yaml::Value) -> Result<String, serde_yaml::Error> {
    let mut output = String::new();

    if let serde_yaml::Value::Mapping(map) = proxy {
        let mut first = true;
        for (key, value) in map {
            let key_str = key.as_str().unwrap_or("");
            let indent = if first { "  - " } else { "    " };
            first = false;

            match key_str {
                "reality-opts" => {
                    // Handle nested reality-opts
                    output.push_str(&format!("{}reality-opts:\n", indent));
                    if let serde_yaml::Value::Mapping(opts) = value {
                        for (k, v) in opts {
                            let k_str = k.as_str().unwrap_or("");
                            let v_str = format_yaml_value(v);
                            output.push_str(&format!("      {}: {}\n", k_str, v_str));
                        }
                    }
                }
                "ws-opts" => {
                    output.push_str(&format!("{}ws-opts:\n", indent));
                    if let serde_yaml::Value::Mapping(opts) = value {
                        for (k, v) in opts {
                            let k_str = k.as_str().unwrap_or("");
                            if k_str == "headers" {
                                output.push_str("      headers:\n");
                                if let serde_yaml::Value::Mapping(headers) = v {
                                    for (hk, hv) in headers {
                                        output.push_str(&format!(
                                            "        {}: {}\n",
                                            hk.as_str().unwrap_or(""),
                                            format_yaml_value(hv)
                                        ));
                                    }
                                }
                            } else {
                                output.push_str(&format!(
                                    "      {}: {}\n",
                                    k_str,
                                    format_yaml_value(v)
                                ));
                            }
                        }
                    }
                }
                "grpc-opts" => {
                    output.push_str(&format!("{}grpc-opts:\n", indent));
                    if let serde_yaml::Value::Mapping(opts) = value {
                        for (k, v) in opts {
                            output.push_str(&format!(
                                "      {}: {}\n",
                                k.as_str().unwrap_or(""),
                                format_yaml_value(v)
                            ));
                        }
                    }
                }
                "h2-opts" => {
                    output.push_str(&format!("{}h2-opts:\n", indent));
                    if let serde_yaml::Value::Mapping(opts) = value {
                        for (k, v) in opts {
                            let k_str = k.as_str().unwrap_or("");
                            if k_str == "host" {
                                output.push_str("      host:\n");
                                if let serde_yaml::Value::Sequence(hosts) = v {
                                    for host in hosts {
                                        output.push_str(&format!(
                                            "        - {}\n",
                                            format_yaml_value(host)
                                        ));
                                    }
                                }
                            } else {
                                output.push_str(&format!(
                                    "      {}: {}\n",
                                    k_str,
                                    format_yaml_value(v)
                                ));
                            }
                        }
                    }
                }
                "plugin-opts" => {
                    // Handle SS plugin-opts (obfs, v2ray-plugin, etc.)
                    output.push_str(&format!("{}plugin-opts:\n", indent));
                    if let serde_yaml::Value::Mapping(opts) = value {
                        for (k, v) in opts {
                            let k_str = k.as_str().unwrap_or("");
                            // Boolean values should output without quotes
                            match v {
                                serde_yaml::Value::Bool(b) => {
                                    output.push_str(&format!("      {}: {}\n", k_str, b));
                                }
                                _ => {
                                    output.push_str(&format!(
                                        "      {}: {}\n",
                                        k_str,
                                        format_yaml_value(v)
                                    ));
                                }
                            }
                        }
                    }
                }
                "alpn" => {
                    output.push_str(&format!("{}alpn:\n", indent));
                    if let serde_yaml::Value::Sequence(seq) = value {
                        for item in seq {
                            output.push_str(&format!("      - {}\n", format_yaml_value(item)));
                        }
                    }
                }
                _ => {
                    // Regular key-value pairs
                    output.push_str(&format!(
                        "{}{}: {}\n",
                        indent,
                        key_str,
                        format_yaml_value(value)
                    ));
                }
            }
        }
    }

    Ok(output)
}

/// Format a proxy group to YAML
/// For url-test/fallback groups, url and interval come BEFORE proxies list
fn format_group_yaml(group: &serde_yaml::Value) -> Result<String, serde_yaml::Error> {
    let mut output = String::new();

    if let serde_yaml::Value::Mapping(map) = group {
        // Extract values we need to reorder
        let name = map.get(serde_yaml::Value::String("name".to_string()));
        let group_type = map.get(serde_yaml::Value::String("type".to_string()));
        let url = map.get(serde_yaml::Value::String("url".to_string()));
        let interval = map.get(serde_yaml::Value::String("interval".to_string()));
        let timeout = map.get(serde_yaml::Value::String("timeout".to_string()));
        let tolerance = map.get(serde_yaml::Value::String("tolerance".to_string()));
        let proxies = map.get(serde_yaml::Value::String("proxies".to_string()));

        // Output in correct order: name, type, url, interval, timeout, tolerance, proxies
        if let Some(n) = name {
            output.push_str(&format!("  - name: {}\n", format_yaml_value_simple(n)));
        }
        if let Some(t) = group_type {
            output.push_str(&format!("    type: {}\n", format_yaml_value_simple(t)));
        }
        // For url-test/fallback: url, interval, timeout, tolerance BEFORE proxies
        if let Some(u) = url {
            output.push_str(&format!("    url: {}\n", format_yaml_value_simple(u)));
        }
        if let Some(i) = interval {
            output.push_str(&format!("    interval: {}\n", format_yaml_value_simple(i)));
        }
        if let Some(t) = timeout {
            output.push_str(&format!("    timeout: {}\n", format_yaml_value_simple(t)));
        }
        if let Some(t) = tolerance {
            output.push_str(&format!("    tolerance: {}\n", format_yaml_value_simple(t)));
        }
        // Proxies list
        if let Some(serde_yaml::Value::Sequence(seq)) = proxies {
            output.push_str("    proxies:\n");
            for item in seq {
                // Don't quote proxy names unless absolutely necessary
                output.push_str(&format!("      - {}\n", format_yaml_value_simple(item)));
            }
        }
    }

    Ok(output)
}

/// Format a YAML value - simple version with minimal quoting
fn format_yaml_value_simple(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => {
            // Only quote if absolutely necessary (contains YAML special chars that break parsing)
            if s.contains(':')
                || s.contains('#')
                || s.contains('\n')
                || s.starts_with(' ')
                || s.ends_with(' ')
                || s.starts_with('"')
                || s.starts_with('\'')
                || s.starts_with('[')
                || s.starts_with('{')
                || s == "true"
                || s == "false"
                || s == "null"
                || s.is_empty()
            {
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                s.clone()
            }
        }
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Null => "null".to_string(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

/// Format a YAML value with proper quoting for strings
fn format_yaml_value(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => {
            // Always quote strings that might contain special characters
            // or that are proxy names/servers
            if s.contains(':')
                || s.contains('#')
                || s.contains('[')
                || s.contains(']')
                || s.contains('{')
                || s.contains('}')
                || s.contains('&')
                || s.contains('*')
                || s.contains('!')
                || s.contains('|')
                || s.contains('>')
                || s.contains('\'')
                || s.contains('"')
                || s.contains('%')
                || s.contains('@')
                || s.contains('`')
                || s.starts_with('-')
                || s.starts_with('?')
                || !s.is_ascii()
            {
                // Use double quotes and escape internal quotes
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            } else if s.is_empty() {
                "\"\"".to_string()
            } else {
                s.clone()
            }
        }
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Null => "null".to_string(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

impl Default for ClashConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
