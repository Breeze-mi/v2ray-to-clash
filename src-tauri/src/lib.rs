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

// ============================================================================
// Tauri Commands
// ============================================================================

/// Convert subscription to Clash YAML config
#[tauri::command]
async fn convert_subscription(request: ConvertRequest) -> Result<ConvertResult, String> {
    let engine = SubscriptionEngine::new(request.timeout_secs)
        .map_err(|e| e.to_string())?;

    engine.convert(request).await.map_err(|e| e.to_string())
}

/// Get list of preset INI configurations
#[tauri::command]
fn get_preset_configs() -> Vec<PresetConfig> {
    SubscriptionEngine::get_preset_configs()
}

/// Parse subscription content without INI config (for preview)
#[tauri::command]
async fn parse_nodes(
    content: String,
    include_regex: Option<String>,
    exclude_regex: Option<String>,
) -> Result<Vec<String>, String> {
    let engine = SubscriptionEngine::new(30).map_err(|e| e.to_string())?;

    // Create a minimal request for parsing
    let request = ConvertRequest {
        subscription: content,
        ini_url: None,
        ini_content: None,
        include_regex,
        exclude_regex,
        rename_pattern: None,
        rename_replacement: None,
        timeout_secs: 30,
    };

    // Get raw content
    let raw = if request.subscription.starts_with("http") {
        engine.convert(ConvertRequest {
            subscription: request.subscription.clone(),
            ini_url: None,
            ini_content: None,
            include_regex: None,
            exclude_regex: None,
            rename_pattern: None,
            rename_replacement: None,
            timeout_secs: 30,
        }).await
            .map_err(|e| e.to_string())?
            .yaml
    } else {
        request.subscription.clone()
    };

    // Parse and filter nodes
    let nodes = parser::parse_subscription_content(&raw).map_err(|e| e.to_string())?;
    let nodes = filter::filter_nodes(
        nodes,
        request.include_regex.as_deref(),
        request.exclude_regex.as_deref(),
    ).map_err(|e| e.to_string())?;

    Ok(nodes.iter().map(|n| n.name().to_string()).collect())
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
