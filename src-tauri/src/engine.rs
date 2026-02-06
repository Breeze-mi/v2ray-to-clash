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

    /// Enable TUN configuration in output
    #[serde(default)]
    pub enable_tun: bool,

    /// Custom User-Agent for fetching subscriptions
    #[serde(default)]
    pub custom_user_agent: Option<String>,

    /// Enable UDP for all nodes (global switch)
    #[serde(default = "default_true")]
    pub enable_udp: bool,

    /// Enable TCP Fast Open for all nodes (global switch)
    #[serde(default)]
    pub enable_tfo: bool,

    /// Skip certificate verification for all nodes (global switch)
    #[serde(default)]
    pub skip_cert_verify: bool,
}

fn default_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
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

    pub fn with_user_agent(timeout_secs: u64, user_agent: &str) -> Result<Self> {
        Ok(Self {
            http_client: HttpClient::with_user_agent(timeout_secs, user_agent)?,
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
        let mut builder = ClashConfigBuilder::new()
            .with_nodes(&nodes)
            .with_global_options(request.enable_udp, request.enable_tfo, request.skip_cert_verify);

        if request.enable_tun {
            builder = builder.with_tun();
        }

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

    /// Resolve subscription content only (for node preview, no conversion).
    /// Fetches URLs and decodes base64 if needed.
    pub async fn resolve_content(&self, content: &str) -> Result<String> {
        let (raw, _) = self.resolve_subscription(content).await?;
        Ok(raw)
    }

    /// Resolve subscription content with subscription info (for node preview).
    /// Returns both the content and subscription info if available.
    pub async fn resolve_content_with_info(&self, content: &str) -> Result<(String, Option<SubscriptionInfo>)> {
        self.resolve_subscription(content).await
    }

    /// Resolve subscription content (fetch URLs, decode base64, etc.)
    /// Returns the content body and subscription info if available from HTTP headers.
    /// Supports multiple input formats:
    /// - Single URL
    /// - Multiple URLs separated by `|` or newlines
    /// - Direct links (vless://, vmess://, etc.)
    /// - Base64 encoded subscription content
    async fn resolve_subscription(&self, content: &str) -> Result<(String, Option<SubscriptionInfo>)> {
        // Step 1: Clean input - remove BOM, normalize line endings, trim whitespace
        let content = clean_input(content);

        // Step 2: Split by | or newlines (subconverter compatible)
        let items: Vec<&str> = if content.contains('|') && !content.contains("://") {
            // Pure URL list separated by |
            content.split('|').collect()
        } else if content.contains('|') {
            // Could be URLs separated by | or a link with | in parameters
            // If it looks like multiple URLs, split; otherwise treat as single
            if content.matches("http").count() > 1 {
                content.split('|').collect()
            } else {
                vec![content.as_str()]
            }
        } else {
            // Split by newlines
            content.lines().collect()
        };

        // Step 3: Process each item
        let mut result_lines = Vec::new();
        let mut first_sub_info: Option<SubscriptionInfo> = None;

        // Separate URLs from direct content
        let mut urls = Vec::new();
        let mut direct_content = Vec::new();

        for item in items {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }

            if item.starts_with("http://") || item.starts_with("https://") {
                urls.push(item.to_string());
            } else {
                direct_content.push(item.to_string());
            }
        }

        // Fetch all URLs concurrently
        if !urls.is_empty() {
            let fetch_futures: Vec<_> = urls.iter()
                .map(|url| self.http_client.fetch_with_info(url))
                .collect();

            let results = futures::future::join_all(fetch_futures).await;

            for result in results {
                match result {
                    Ok(fetched) => {
                        // Keep the first subscription info we encounter
                        if first_sub_info.is_none() {
                            first_sub_info = fetched.subscription_info;
                        }
                        // The fetched content might be base64 encoded, decode it
                        let decoded_content = decode_subscription_body(&fetched.body);
                        // Append fetched content
                        for sub_line in decoded_content.lines() {
                            let sub_line = sub_line.trim();
                            if !sub_line.is_empty() {
                                result_lines.push(sub_line.to_string());
                            }
                        }
                    }
                    Err(_e) => {
                        // Silently skip failed URLs; the user will see
                        // missing nodes in the preview / conversion result
                    }
                }
            }
        }

        // Add direct content
        result_lines.extend(direct_content);

        Ok((result_lines.join("\n"), first_sub_info))
    }

    /// Get predefined INI config URLs
    pub fn get_preset_configs() -> Vec<PresetConfig> {
        vec![
            // ==================== ACL4SSR 系列 ====================
            PresetConfig {
                name: "ACL4SSR_Online".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini".to_string(),
                description: "ACL4SSR 默认版 分组比较全".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Mini".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini".to_string(),
                description: "ACL4SSR 精简版 少量规则".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Mini_NoAuto".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini".to_string(),
                description: "ACL4SSR 精简版 无自动测速".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Full".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini".to_string(),
                description: "ACL4SSR 全分组版 带测试分组".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_Full_NoAuto".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini".to_string(),
                description: "ACL4SSR 全分组版 无自动测速".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_AdblockPlus".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini".to_string(),
                description: "ACL4SSR 全分组版 带去广告".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_MultiMode".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini".to_string(),
                description: "ACL4SSR 全分组版 多模式".to_string(),
            },
            PresetConfig {
                name: "ACL4SSR_Online_NoReject".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini".to_string(),
                description: "ACL4SSR 无广告拦截规则".to_string(),
            },
            // ==================== 其他规则集 ====================
            PresetConfig {
                name: "全网搜集规则".to_string(),
                url: "https://raw.githubusercontent.com/cutethotw/ClashRule/main/GeneralClashRule.ini".to_string(),
                description: "全网搜集 分流较细致".to_string(),
            },
            PresetConfig {
                name: "分区域故障转移".to_string(),
                url: "https://raw.githubusercontent.com/cutethotw/ClashRule/main/GeneralClashRule-Fallback.ini".to_string(),
                description: "按区域故障转移".to_string(),
            },
            PresetConfig {
                name: "NeteaseUnblock".to_string(),
                url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Netflix.ini".to_string(),
                description: "ACL4SSR Netflix 优化版".to_string(),
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

// ============================================================================
// Helper functions for input cleaning and decoding
// ============================================================================

/// Clean input content: remove BOM, normalize line endings, trim whitespace
fn clean_input(content: &str) -> String {
    let mut content = content.to_string();

    // Remove UTF-8 BOM if present
    if content.starts_with('\u{FEFF}') {
        content = content[3..].to_string();
    }
    // Also handle the raw BOM bytes in case they weren't decoded
    if content.starts_with("\u{EF}\u{BB}\u{BF}") {
        content = content[3..].to_string();
    }

    // Normalize line endings: \r\n -> \n, \r -> \n
    content = content.replace("\r\n", "\n").replace('\r', "\n");

    // Trim overall
    content.trim().to_string()
}

/// Decode subscription body if it's base64 encoded
/// Returns decoded content or original content if not base64
fn decode_subscription_body(body: &str) -> String {
    use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine as _};

    let body = clean_input(body);

    // Check if content looks like base64 (no protocol prefix, only valid base64 chars)
    let is_likely_base64 = !body.contains("://")
        && !body.contains('\n')
        && body.len() > 20  // base64 content is typically longer
        && body.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
                || c == '-' || c == '_'
        });

    // Also check if it contains newlines but ALL lines look like base64
    let lines_all_base64 = body.lines().all(|line| {
        let line = line.trim();
        line.is_empty() || (!line.contains("://") && line.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
                || c == '-' || c == '_'
        }))
    });

    if is_likely_base64 || (body.lines().count() == 1 && lines_all_base64) {
        // Try to decode as base64
        let encoded = body.replace(['\n', '\r', ' '], "");

        // Try different base64 variants
        let decoded = STANDARD.decode(&encoded)
            .or_else(|_| URL_SAFE.decode(&encoded))
            .or_else(|_| URL_SAFE_NO_PAD.decode(&encoded))
            .or_else(|_| {
                // Try adding padding if missing
                let padded = match encoded.len() % 4 {
                    2 => format!("{}==", encoded),
                    3 => format!("{}=", encoded),
                    _ => encoded.clone(),
                };
                STANDARD.decode(&padded)
                    .or_else(|_| URL_SAFE.decode(&padded))
            });

        if let Ok(bytes) = decoded {
            if let Ok(s) = String::from_utf8(bytes) {
                // Successfully decoded and it's valid UTF-8
                // Recursively clean the decoded content
                return clean_input(&s);
            }
        }
    }

    // Not base64 or failed to decode, return as-is
    body
}
