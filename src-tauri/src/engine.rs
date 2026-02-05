//! Main subscription conversion engine
//! Orchestrates fetching, parsing, filtering, and YAML generation

use serde::{Deserialize, Serialize};

use crate::clash_config::ClashConfigBuilder;
use crate::error::{ConvertError, Result};
use crate::filter::{filter_nodes, rename_nodes, deduplicate_nodes};
use crate::http_client::{HttpClient, SubscriptionInfo};
use crate::ini_parser::parse_ini_config;
use crate::parser::parse_subscription_content;

/// Conversion request from frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertRequest {
    /// Subscription content (links or URLs, one per line)
    pub subscription: String,

    /// Remote INI config URL (optional)
    #[serde(default)]
    pub ini_url: Option<String>,

    /// Custom INI content (if not using remote URL)
    #[serde(default)]
    pub ini_content: Option<String>,

    /// Include nodes matching this regex
    #[serde(default)]
    pub include_regex: Option<String>,

    /// Exclude nodes matching this regex
    #[serde(default)]
    pub exclude_regex: Option<String>,

    /// Regex pattern for renaming nodes
    #[serde(default)]
    pub rename_pattern: Option<String>,

    /// Replacement string for renaming
    #[serde(default)]
    pub rename_replacement: Option<String>,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

/// Conversion result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertResult {
    /// Generated YAML config
    pub yaml: String,

    /// Number of nodes parsed
    pub node_count: usize,

    /// Number of nodes after filtering
    pub filtered_count: usize,

    /// Number of proxy groups
    pub group_count: usize,

    /// Number of rules
    pub rule_count: usize,

    /// Warnings during conversion
    pub warnings: Vec<String>,

    /// Subscription traffic/expiry info (if available from header)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_info: Option<SubscriptionInfo>,
}

/// Main conversion engine
pub struct SubscriptionEngine {
    http_client: HttpClient,
}

impl SubscriptionEngine {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        Ok(Self {
            http_client: HttpClient::new(timeout_secs)?,
        })
    }

    /// Main conversion function
    pub async fn convert(&self, request: ConvertRequest) -> Result<ConvertResult> {
        let mut warnings = Vec::new();

        // Step 1: Parse subscription content
        let (raw_content, subscription_info) = self.resolve_subscription(&request.subscription).await?;
        let mut nodes = parse_subscription_content(&raw_content)?;
        let initial_count = nodes.len();

        if nodes.is_empty() {
            return Err(ConvertError::Internal("No valid nodes found in subscription".into()));
        }

        // Step 2: Deduplicate nodes
        let before_dedup = nodes.len();
        nodes = deduplicate_nodes(nodes);
        if nodes.len() < before_dedup {
            warnings.push(format!(
                "Removed {} duplicate nodes",
                before_dedup - nodes.len()
            ));
        }

        // Step 3: Apply node filtering
        nodes = filter_nodes(
            nodes,
            request.include_regex.as_deref(),
            request.exclude_regex.as_deref(),
        )?;

        if nodes.is_empty() {
            return Err(ConvertError::Internal(
                "All nodes were filtered out. Check your filter patterns.".into()
            ));
        }

        // Step 4: Apply node renaming
        if let (Some(pattern), Some(replacement)) = (&request.rename_pattern, &request.rename_replacement) {
            if !pattern.is_empty() {
                nodes = rename_nodes(nodes, pattern, replacement)?;
            }
        }

        let filtered_count = nodes.len();

        // Step 5: Load INI config (if provided)
        let ini_config = if let Some(url) = &request.ini_url {
            if !url.is_empty() {
                match self.http_client.fetch(url).await {
                    Ok(content) => match parse_ini_config(&content) {
                        Ok(config) => Some(config),
                        Err(e) => {
                            warnings.push(format!("Failed to parse INI config: {}", e));
                            None
                        }
                    },
                    Err(e) => {
                        warnings.push(format!("Failed to fetch INI config: {}", e));
                        None
                    }
                }
            } else {
                None
            }
        } else if let Some(content) = &request.ini_content {
            if !content.is_empty() {
                match parse_ini_config(content) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        warnings.push(format!("Failed to parse INI content: {}", e));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Step 6: Build Clash config
        let builder = ClashConfigBuilder::new().with_nodes(&nodes);

        let (builder, group_count, rule_count) = if let Some(ref ini) = ini_config {
            let group_count = ini.proxy_groups.len();
            let rule_count = ini.rules.len() + ini.ruleset_urls.len();
            (builder.with_ini_config(ini, &nodes), group_count, rule_count)
        } else {
            let builder = builder
                .with_default_groups(&nodes)
                .with_default_rules();
            (builder, 5, 7) // Default has 5 groups and 7 rules
        };

        // Step 7: Generate YAML
        let yaml = builder.build_yaml().map_err(|e| {
            ConvertError::YamlSerializeError(e.to_string())
        })?;

        Ok(ConvertResult {
            yaml,
            node_count: initial_count,
            filtered_count,
            group_count,
            rule_count,
            warnings,
            subscription_info,
        })
    }

    /// Resolve subscription content (fetch URLs, decode base64, etc.)
    /// Returns the content body and subscription info if available from HTTP headers.
    async fn resolve_subscription(&self, content: &str) -> Result<(String, Option<SubscriptionInfo>)> {
        let content = content.trim();

        // Check if content is a single URL
        if content.starts_with("http://") || content.starts_with("https://") {
            if content.lines().count() == 1 {
                // Single URL - fetch it with subscription info
                let result = self.http_client.fetch_with_info(content).await?;
                return Ok((result.body, result.subscription_info));
            }
        }

        // Check if content contains multiple URLs or mixed content
        let mut result_lines = Vec::new();
        let mut first_sub_info: Option<SubscriptionInfo> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with("http://") || line.starts_with("https://") {
                // Fetch URL content with info
                match self.http_client.fetch_with_info(line).await {
                    Ok(fetched) => {
                        // Keep the first subscription info we encounter
                        if first_sub_info.is_none() {
                            first_sub_info = fetched.subscription_info;
                        }
                        // Append fetched content
                        for sub_line in fetched.body.lines() {
                            if !sub_line.trim().is_empty() {
                                result_lines.push(sub_line.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to fetch {}: {}", line, e);
                    }
                }
            } else {
                // Direct content (links or base64)
                result_lines.push(line.to_string());
            }
        }

        Ok((result_lines.join("\n"), first_sub_info))
    }

    /// Get predefined INI config URLs
    pub fn get_preset_configs() -> Vec<PresetConfig> {
        vec![
            PresetConfig {
                name: "ACL4SSR_Online".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini".to_string(),
                description: "默认版 分组比较全".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Mini".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini".to_string(),
                description: "精简版 少量规则".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Full".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini".to_string(),
                description: "全分组版 带用于测试的小分组".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Full_NoAuto".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini".to_string(),
                description: "全分组版 不带自动测速".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_AdblockPlus".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini".to_string(),
                description: "全分组版 带去广告".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_MultiCountry".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini".to_string(),
                description: "全分组版 多模式".to_string(),
            },
        ]
    }
}

/// Preset INI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetConfig {
    pub name: String,
    pub url: String,
    pub description: String,
}
