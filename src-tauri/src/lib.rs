//! LocalSub - Local Subscription Converter for Clash
//!
//! A privacy-focused subscription conversion tool that runs entirely locally.

pub mod error;
pub mod node;
pub mod parser;
pub mod filter;
pub mod ini_parser;
pub mod clash_config;
pub mod http_client;
pub mod engine;

use engine::{ConvertRequest, ConvertResult, PresetConfig, SubscriptionEngine};
use http_client::SubscriptionInfo;
use serde::Serialize;

// ============================================================================
// Tauri Commands
// ============================================================================

/// Node preview info for frontend display
#[derive(Debug, Clone, Serialize)]
pub struct NodePreviewItem {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
}

/// Result of parsing nodes for preview
#[derive(Debug, Clone, Serialize)]
pub struct ParseNodesResult {
    pub nodes: Vec<NodePreviewItem>,
    pub subscription_info: Option<SubscriptionInfo>,
}

/// Convert subscription to Clash YAML config
#[tauri::command]
async fn convert_subscription(request: ConvertRequest) -> Result<ConvertResult, String> {
    let engine = if let Some(ref ua) = request.custom_user_agent {
        if !ua.is_empty() {
            SubscriptionEngine::with_user_agent(request.timeout_secs, ua)
        } else {
            SubscriptionEngine::new(request.timeout_secs)
        }
    } else {
        SubscriptionEngine::new(request.timeout_secs)
    }.map_err(|e| e.to_string())?;

    engine.convert(request).await.map_err(|e| e.to_string())
}

/// Get list of preset INI configurations
#[tauri::command]
fn get_preset_configs() -> Vec<PresetConfig> {
    SubscriptionEngine::get_preset_configs()
}

/// Parse subscription content and return node details for preview
#[tauri::command]
async fn parse_nodes(
    content: String,
    include_regex: Option<String>,
    exclude_regex: Option<String>,
) -> Result<ParseNodesResult, String> {
    let engine = SubscriptionEngine::new(30).map_err(|e| e.to_string())?;

    // Resolve subscription content (fetch URLs if needed) with subscription info
    let (raw, subscription_info) = engine.resolve_content_with_info(&content).await.map_err(|e| e.to_string())?;

    // Parse nodes
    let nodes = parser::parse_subscription_content(&raw).map_err(|e| e.to_string())?;

    // Filter
    let nodes = filter::filter_nodes(
        nodes,
        include_regex.as_deref(),
        exclude_regex.as_deref(),
    ).map_err(|e| e.to_string())?;

    // Deduplicate
    let nodes = filter::deduplicate_nodes(nodes);

    Ok(ParseNodesResult {
        nodes: nodes.iter().map(|n| NodePreviewItem {
            name: n.name().to_string(),
            protocol: n.protocol_type().to_string(),
            server: n.server().to_string(),
            port: n.port(),
        }).collect(),
        subscription_info,
    })
}

/// Validate regex pattern
#[tauri::command]
fn validate_regex(pattern: String) -> Result<bool, String> {
    match regex::Regex::new(&pattern) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Fetch remote content (for testing URLs)
#[tauri::command]
async fn fetch_url(url: String, timeout_secs: Option<u64>) -> Result<String, String> {
    let client = http_client::HttpClient::new(timeout_secs.unwrap_or(30))
        .map_err(|e| e.to_string())?;

    client.fetch(&url).await.map_err(|e| e.to_string())
}

// ============================================================================
// Tauri App Entry
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            convert_subscription,
            get_preset_configs,
            parse_nodes,
            validate_regex,
            fetch_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
