//! Universal node parser supporting multiple proxy protocols
//! Parses VLESS, VMess, Shadowsocks, ShadowsocksR, Trojan, Hysteria2, TUIC URLs

use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine as _};
use indexmap::IndexMap;
use url::Url;

use crate::error::{ConvertError, Result};
use crate::node::*;

/// Parse subscription content (supports mixed links and base64 encoded content)
/// Continues parsing even if some links fail, collecting warnings.
/// Returns error only if no valid nodes are found.
pub fn parse_subscription_content(content: &str) -> Result<Vec<Node>> {
    let content = clean_subscription_input(content);

    // Try to decode as base64 first
    let decoded = if looks_like_base64(&content) {
        match decode_base64_flexible(&content) {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes).to_string();
                clean_subscription_input(&s)
            }
            Err(_) => content.to_string(),
        }
    } else {
        content.to_string()
    };

    let mut nodes = Vec::new();
    let mut warnings = Vec::new();

    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_single_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => {
                // Collect warning but continue parsing other nodes
                let truncated_link = if line.len() > 50 {
                    format!("{}...", &line[..50])
                } else {
                    line.to_string()
                };
                warnings.push(format!("{}: {}", truncated_link, e));
            }
        }
    }

    // Warnings are collected but not printed to avoid stderr pollution
    // In future, could be returned alongside nodes or logged via proper logging crate
    let _ = &warnings; // Suppress unused warning while keeping collection for error context

    // Only fail if we found no valid nodes at all
    if nodes.is_empty() && !warnings.is_empty() {
        return Err(ConvertError::Internal(
            format!("No valid proxy nodes found. {} link(s) failed to parse. First error: {}",
                warnings.len(),
                warnings.first().unwrap_or(&"Unknown error".to_string())
            )
        ));
    }

    Ok(nodes)
}

/// Clean subscription input: BOM, line endings, trailing spaces
fn clean_subscription_input(content: &str) -> String {
    // Remove UTF-8 BOM
    let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);

    // Normalize line endings: \r\n -> \n, \r -> \n
    let content = content.replace("\r\n", "\n").replace('\r', "\n");

    content.trim().to_string()
}

/// Check if content looks like base64 encoded
fn looks_like_base64(content: &str) -> bool {
    let content = content.replace(['\n', '\r', ' '], "");
    // Base64 content typically doesn't contain protocol prefixes
    // Support both standard (+/) and URL-safe (-_) base64
    !content.contains("://") && content.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
            || c == '-' || c == '_'
    })
}

/// Decode base64 flexibly, trying STANDARD, URL_SAFE, and URL_SAFE_NO_PAD engines.
/// SS links often use URL-safe base64 with or without padding.
fn decode_base64_flexible(encoded: &str) -> Result<Vec<u8>> {
    let encoded = encoded.replace(['\n', '\r', ' '], "");
    STANDARD.decode(&encoded)
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
        })
        .map_err(|e| ConvertError::Base64DecodeError(e.to_string()))
}

/// Parse a single proxy link
pub fn parse_single_link(link: &str) -> Result<Node> {
    let link = link.trim();

    if link.starts_with("vless://") {
        parse_vless(link)
    } else if link.starts_with("vmess://") {
        parse_vmess(link)
    } else if link.starts_with("ss://") {
        parse_shadowsocks(link)
    } else if link.starts_with("ssr://") {
        parse_ssr(link)
    } else if link.starts_with("trojan://") {
        parse_trojan(link)
    } else if link.starts_with("hysteria2://") || link.starts_with("hy2://") {
        parse_hysteria2(link)
    } else if link.starts_with("hysteria://") || link.starts_with("hy://") {
        parse_hysteria(link)
    } else if link.starts_with("tuic://") {
        parse_tuic(link)
    } else if link.starts_with("wireguard://") || link.starts_with("wg://") {
        parse_wireguard(link)
    } else {
        Err(ConvertError::UnsupportedProtocol(
            link.split("://").next().unwrap_or("unknown").to_string()
        ))
    }
}

// ============================================================================
// VLESS Parser
// ============================================================================

fn parse_vless(link: &str) -> Result<Node> {
    let url = Url::parse(link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return Err(ConvertError::MissingField {
            field: "uuid".into(),
            context: "VLESS URL".into(),
        });
    }

    let server = url.host_str()
        .ok_or_else(|| ConvertError::MissingField {
            field: "server".into(),
            context: "VLESS URL".into(),
        })?
        .to_string();

    let port = url.port().unwrap_or(443);
    let name = url_decode(url.fragment().unwrap_or(&server));

    // Parse query parameters
    let params: IndexMap<String, String> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Helper to get non-empty string parameter
    let get_param = |key: &str| -> Option<String> {
        params.get(key).filter(|v| !v.is_empty()).cloned()
    };

    let network = get_param("type").unwrap_or_else(|| "tcp".to_string());
    let security = get_param("security").unwrap_or_else(|| "none".to_string());

    // Parse alpn - filter out empty strings
    let alpn = get_param("alpn").and_then(|v| {
        let list: Vec<String> = v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if list.is_empty() { None } else { Some(list) }
    });

    let mut node = VlessNode {
        name,
        server,
        port,
        uuid,
        flow: get_param("flow"),
        network: network.clone(),
        tls: Some(security == "tls" || security == "reality"),
        servername: get_param("sni"),
        skip_cert_verify: params.get("allowInsecure").map(|v| v == "1" || v == "true"),
        // fp param = uTLS client fingerprint, NOT certificate fingerprint
        client_fingerprint: get_param("fp"),
        alpn,
        reality_opts: None,
        ws_opts: None,
        grpc_opts: None,
        h2_opts: None,
        packet_encoding: get_param("packetEncoding"),
    };

    // Reality options
    if security == "reality" {
        if let Some(pbk) = params.get("pbk") {
            node.reality_opts = Some(RealityOpts {
                public_key: pbk.clone(),
                short_id: params.get("sid").cloned(),
            });
        }
        // For Reality, client-fingerprint is required and cannot be empty
        // Default to "chrome" if not specified
        if node.client_fingerprint.is_none() || node.client_fingerprint.as_ref().map(|s| s.is_empty()).unwrap_or(false) {
            node.client_fingerprint = Some("chrome".to_string());
        }
    }

    // Network-specific options
    match network.as_str() {
        "ws" => {
            let mut headers = IndexMap::new();
            if let Some(host) = get_param("host") {
                headers.insert("Host".to_string(), host);
            }
            node.ws_opts = Some(WsOpts {
                path: get_param("path"),
                headers: if headers.is_empty() { None } else { Some(headers) },
            });
        }
        "grpc" => {
            node.grpc_opts = Some(GrpcOpts {
                grpc_service_name: get_param("serviceName"),
            });
        }
        "h2" => {
            let host = get_param("host").and_then(|v| {
                let list: Vec<String> = v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if list.is_empty() { None } else { Some(list) }
            });
            node.h2_opts = Some(H2Opts {
                path: get_param("path"),
                host,
            });
        }
        _ => {}
    }

    Ok(Node::Vless(node))
}

// ============================================================================
// VMess Parser
// ============================================================================

fn parse_vmess(link: &str) -> Result<Node> {
    // VMess links are typically base64 encoded JSON after "vmess://"
    let encoded = link.strip_prefix("vmess://")
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "vmess".into(),
            reason: "Missing vmess:// prefix".into(),
        })?;

    let decoded = decode_base64_flexible(encoded.trim())?;

    let json: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| ConvertError::InvalidNodeFormat {
            protocol: "vmess".into(),
            reason: format!("Invalid JSON: {}", e),
        })?;

    let get_str = |key: &str| -> Option<String> {
        json.get(key).and_then(|v| {
            match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Null => None,
                _ => {
                    // Convert numbers/bools to string
                    let s = v.to_string();
                    let s = s.trim_matches('"');
                    if s.is_empty() || s == "null" {
                        None
                    } else {
                        Some(s.to_string())
                    }
                }
            }
        })
    };

    let get_u32 = |key: &str| -> Option<u32> {
        json.get(key).and_then(|v| {
            if v.is_number() {
                v.as_u64().map(|n| n as u32)
            } else if v.is_string() {
                v.as_str().and_then(|s| s.parse().ok())
            } else {
                None
            }
        })
    };

    let server = get_str("add")
        .ok_or_else(|| ConvertError::MissingField {
            field: "add (server)".into(),
            context: "VMess config".into(),
        })?;

    let port = get_u32("port").unwrap_or(443) as u16;

    let uuid = get_str("id")
        .ok_or_else(|| ConvertError::MissingField {
            field: "id (uuid)".into(),
            context: "VMess config".into(),
        })?;

    let name = get_str("ps").unwrap_or_else(|| server.clone());
    let network = get_str("net").unwrap_or_else(|| "tcp".to_string());
    // tls field: "tls" means true, empty string or missing means false
    // Some VMess configs use "none" or "" for no TLS
    let tls = get_str("tls").map(|v| !v.is_empty() && v != "none" && v == "tls");

    // Parse skip-cert-verify (can be bool or string "true"/"false")
    let skip_cert_verify = json.get("skip-cert-verify").and_then(|v| {
        if v.is_boolean() {
            v.as_bool()
        } else if v.is_string() {
            Some(v.as_str().unwrap_or("false") == "true")
        } else {
            None
        }
    });

    // servername: prefer "sni", fallback to "host" for WS connections
    // Handle empty strings as missing
    let servername = get_str("sni")
        .filter(|s| !s.is_empty())
        .or_else(|| {
            if network == "ws" {
                get_str("host").filter(|s| !s.is_empty())
            } else {
                None
            }
        });

    let mut node = VmessNode {
        name,
        server,
        port,
        uuid,
        alterId: get_u32("aid").unwrap_or(0),
        cipher: get_str("scy").or_else(|| get_str("security")).unwrap_or_else(|| "auto".to_string()),
        network: Some(network.clone()),
        tls,
        skip_cert_verify,
        servername,
        ws_opts: None,
        h2_opts: None,
        grpc_opts: None,
    };

    // Network-specific options
    match network.as_str() {
        "ws" => {
            let mut headers = IndexMap::new();
            if let Some(host) = get_str("host") {
                headers.insert("Host".to_string(), host);
            }
            node.ws_opts = Some(WsOpts {
                path: get_str("path"),
                headers: if headers.is_empty() { None } else { Some(headers) },
            });
        }
        "h2" => {
            let host = get_str("host").map(|v| {
                let list: Vec<String> = v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                list
            }).filter(|list| !list.is_empty());
            node.h2_opts = Some(H2Opts {
                path: get_str("path"),
                host,
            });
        }
        "grpc" => {
            // grpc serviceName can come from different fields
            let service_name = get_str("path")
                .or_else(|| get_str("serviceName"))
                .or_else(|| get_str("grpc-service-name"));
            node.grpc_opts = Some(GrpcOpts {
                grpc_service_name: service_name,
            });
        }
        _ => {}
    }

    Ok(Node::Vmess(node))
}

// ============================================================================
// Shadowsocks Parser
// ============================================================================

fn parse_shadowsocks(link: &str) -> Result<Node> {
    // SS URLs can be in multiple formats:
    // 1. SIP002: ss://BASE64(method:password)@host:port/?plugin=...#name
    // 2. Legacy: ss://BASE64(method:password@host:port)#name

    let link = link.strip_prefix("ss://")
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: "Missing ss:// prefix".into(),
        })?;

    // Extract fragment (name)
    let (link, name) = if let Some(idx) = link.find('#') {
        (&link[..idx], url_decode(&link[idx + 1..]))
    } else {
        (link, String::new())
    };

    // Extract query parameters (for plugin)
    let (link, query_params) = if let Some(idx) = link.find('?') {
        (&link[..idx], Some(&link[idx + 1..]))
    } else {
        (link, None)
    };

    // Parse plugin parameters if present
    let (plugin, plugin_opts) = parse_ss_plugin(query_params);

    // Try format 1: BASE64@host:port (SIP002)
    if let Some(at_idx) = link.rfind('@') {
        let encoded = &link[..at_idx];
        let server_port = &link[at_idx + 1..];
        // Remove trailing slash that may remain from /?plugin=... pattern
        let server_port = server_port.trim_end_matches('/');

        // Decode method:password
        let decoded = decode_base64_flexible(encoded)?;
        let decoded_str = String::from_utf8_lossy(&decoded);

        let (cipher, password) = decoded_str.split_once(':')
            .ok_or_else(|| ConvertError::InvalidNodeFormat {
                protocol: "ss".into(),
                reason: "Invalid method:password format".into(),
            })?;

        // Validate cipher
        if !is_valid_ss_cipher(cipher) {
            return Err(ConvertError::InvalidNodeFormat {
                protocol: "ss".into(),
                reason: format!("Unsupported cipher: {}", cipher),
            });
        }

        // Parse server:port
        let (server, port) = parse_host_port(server_port)?;

        let name = if name.is_empty() { server.clone() } else { name };

        return Ok(Node::Shadowsocks(ShadowsocksNode {
            name,
            server,
            port,
            cipher: cipher.to_string(),
            password: password.to_string(),
            udp: Some(true),
            plugin,
            plugin_opts,
        }));
    }

    // Try format 2: full base64 (Legacy)
    let decoded = decode_base64_flexible(link)?;
    let decoded_str = String::from_utf8_lossy(&decoded);

    // Parse method:password@host:port
    let (method_pass, server_port) = decoded_str.rsplit_once('@')
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: "Missing @ separator".into(),
        })?;

    let (cipher, password) = method_pass.split_once(':')
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: "Invalid method:password format".into(),
        })?;

    // Validate cipher
    if !is_valid_ss_cipher(cipher) {
        return Err(ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: format!("Unsupported cipher: {}", cipher),
        });
    }

    let (server, port) = parse_host_port(server_port)?;
    let name = if name.is_empty() { server.clone() } else { name };

    Ok(Node::Shadowsocks(ShadowsocksNode {
        name,
        server,
        port,
        cipher: cipher.to_string(),
        password: password.to_string(),
        udp: Some(true),
        plugin,
        plugin_opts,
    }))
}

/// Parse SS plugin parameter from query string
/// Format: plugin=obfs-local;obfs=http;obfs-host=example.com
/// or: plugin=v2ray-plugin;mode=websocket;host=example.com;path=/ws
fn parse_ss_plugin(query: Option<&str>) -> (Option<String>, Option<IndexMap<String, String>>) {
    let query = match query {
        Some(q) => q,
        None => return (None, None),
    };

    // Find plugin parameter
    let plugin_value = query.split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            if key == "plugin" {
                Some(url_decode(value))
            } else {
                None
            }
        });

    let plugin_str = match plugin_value {
        Some(p) => p,
        None => return (None, None),
    };

    // Parse plugin string: name;opt1=val1;opt2=val2
    let parts: Vec<&str> = plugin_str.split(';').collect();
    if parts.is_empty() {
        return (None, None);
    }

    let plugin_name = parts[0];
    let mut opts = IndexMap::new();

    // Parse plugin options
    for part in &parts[1..] {
        if let Some((key, value)) = part.split_once('=') {
            opts.insert(key.to_string(), value.to_string());
        }
    }

    // Map SIP003 plugin names to Clash plugin names
    let (clash_plugin, clash_opts) = match plugin_name {
        "obfs-local" | "simple-obfs" => {
            // Map obfs-local to Clash "obfs" plugin
            // obfs=http -> mode: http
            // obfs-host=example.com -> host: example.com
            let mut clash_opts = IndexMap::new();
            if let Some(obfs_mode) = opts.get("obfs") {
                clash_opts.insert("mode".to_string(), obfs_mode.clone());
            }
            if let Some(obfs_host) = opts.get("obfs-host") {
                clash_opts.insert("host".to_string(), obfs_host.clone());
            }
            ("obfs".to_string(), clash_opts)
        }
        "v2ray-plugin" => {
            // v2ray-plugin maps directly, but rename some options
            // mode=websocket -> mode: websocket
            let mut clash_opts = IndexMap::new();
            if let Some(mode) = opts.get("mode") {
                clash_opts.insert("mode".to_string(), mode.clone());
            }
            if let Some(host) = opts.get("host") {
                clash_opts.insert("host".to_string(), host.clone());
            }
            if let Some(path) = opts.get("path") {
                clash_opts.insert("path".to_string(), path.clone());
            }
            // tls should be stored as "true" string, will be converted to bool in to_clash_map
            if opts.get("tls").map(|v| v == "true" || v == "1" || v.is_empty()).unwrap_or(false)
                || plugin_str.contains(";tls")  // handle ";tls" without value
            {
                clash_opts.insert("tls".to_string(), "true".to_string());
            }
            if let Some(mux) = opts.get("mux") {
                clash_opts.insert("mux".to_string(), mux.clone());
            }
            if let Some(skip) = opts.get("skip-cert-verify") {
                clash_opts.insert("skip-cert-verify".to_string(), skip.clone());
            }
            ("v2ray-plugin".to_string(), clash_opts)
        }
        _ => {
            // Unknown plugin, pass through as-is
            (plugin_name.to_string(), opts)
        }
    };

    if clash_opts.is_empty() {
        (Some(clash_plugin), None)
    } else {
        (Some(clash_plugin), Some(clash_opts))
    }
}

// ============================================================================
// ShadowsocksR (SSR) Parser
// ============================================================================

fn parse_ssr(link: &str) -> Result<Node> {
    // SSR format: ssr://BASE64(server:port:protocol:method:obfs:BASE64(password)/?params)
    // URL-safe base64 with optional padding
    // Note: Some SSR links have params OUTSIDE base64: ssr://BASE64.../?remarks=BASE64
    let content = link.strip_prefix("ssr://")
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ssr".into(),
            reason: "Missing ssr:// prefix".into(),
        })?;

    // Check if params are outside base64 (indicated by /? or ? before valid base64 chars end)
    let (encoded, external_query) = if let Some(idx) = content.find("/?") {
        (&content[..idx], Some(&content[idx + 2..]))
    } else if let Some(idx) = content.find('?') {
        // Only split if '?' appears after what looks like base64
        // Base64 URL-safe chars: A-Z a-z 0-9 - _ =
        let before = &content[..idx];
        if before.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=') {
            (&content[..idx], Some(&content[idx + 1..]))
        } else {
            (content, None)
        }
    } else {
        (content, None)
    };

    let decoded = decode_base64_flexible(encoded.trim())?;
    let decoded_str = String::from_utf8_lossy(&decoded);

    // Split at "/?" or "?" to separate main part from internal query params
    let (main_part, internal_query) = if let Some(idx) = decoded_str.find("/?") {
        (&decoded_str[..idx], Some(&decoded_str[idx + 2..]))
    } else if let Some(idx) = decoded_str.find('?') {
        (&decoded_str[..idx], Some(&decoded_str[idx + 1..]))
    } else {
        (decoded_str.as_ref(), None)
    };

    // Merge internal and external query params (external takes precedence for same keys)
    let query_part = match (internal_query, external_query) {
        (Some(i), Some(e)) => Some(format!("{}&{}", i, e)),
        (Some(i), None) => Some(i.to_string()),
        (None, Some(e)) => Some(e.to_string()),
        (None, None) => None,
    };

    // Parse main part: server:port:protocol:method:obfs:base64(password)
    let parts: Vec<&str> = main_part.splitn(6, ':').collect();
    if parts.len() < 6 {
        return Err(ConvertError::InvalidNodeFormat {
            protocol: "ssr".into(),
            reason: format!("Expected 6 parts in main section, got {}", parts.len()),
        });
    }

    // Handle IPv6 server (may not be in brackets in SSR format)
    let (server, rest_parts) = if main_part.starts_with('[') {
        // IPv6 with brackets: [::1]:port:protocol:method:obfs:password
        if let Some(bracket_end) = main_part.find(']') {
            let server = &main_part[1..bracket_end];
            let rest = &main_part[bracket_end + 2..]; // Skip ]:
            (server.to_string(), rest.splitn(5, ':').collect::<Vec<_>>())
        } else {
            return Err(ConvertError::InvalidNodeFormat {
                protocol: "ssr".into(),
                reason: "Invalid IPv6 format".into(),
            });
        }
    } else {
        // Regular format or IPv6 without brackets
        // Count colons to detect IPv6
        let colon_count = main_part.matches(':').count();
        if colon_count > 5 {
            // Likely IPv6 without brackets, find where the port starts
            // SSR uses server:port:protocol:method:obfs:password
            // For IPv6, we need to find the pattern by looking for known protocol values
            // This is tricky - try parsing from the end
            let all_parts: Vec<&str> = main_part.split(':').collect();
            let num_parts = all_parts.len();
            if num_parts >= 6 {
                // Last 5 parts are: port, protocol, method, obfs, password
                let password_b64 = all_parts[num_parts - 1];
                let obfs = all_parts[num_parts - 2];
                let method = all_parts[num_parts - 3];
                let protocol = all_parts[num_parts - 4];
                let port = all_parts[num_parts - 5];
                // Everything before is the server
                let server = all_parts[..num_parts - 5].join(":");
                (server, vec![port, protocol, method, obfs, password_b64])
            } else {
                return Err(ConvertError::InvalidNodeFormat {
                    protocol: "ssr".into(),
                    reason: "Cannot parse IPv6 server".into(),
                });
            }
        } else {
            (parts[0].to_string(), parts[1..].to_vec())
        }
    };

    let port: u16 = rest_parts.first()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ssr".into(),
            reason: "Invalid port".into(),
        })?;

    let protocol = rest_parts.get(1).unwrap_or(&"origin").to_string();
    let method = rest_parts.get(2).unwrap_or(&"aes-256-cfb").to_string();
    let obfs = rest_parts.get(3).unwrap_or(&"plain").to_string();
    let password_b64 = rest_parts.get(4).unwrap_or(&"");

    // Validate cipher
    if !is_valid_ssr_cipher(&method) {
        return Err(ConvertError::InvalidNodeFormat {
            protocol: "ssr".into(),
            reason: format!("Unsupported cipher: {}", method),
        });
    }

    // Decode password (also URL-safe base64)
    let password = decode_base64_flexible(password_b64)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    // Parse query parameters (all values are base64 encoded)
    let mut name = server.clone();
    let mut obfs_param = None;
    let mut protocol_param = None;
    let mut group = None;

    if let Some(ref query) = query_part {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_value = decode_base64_flexible(value)
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_else(|_| value.to_string());

                match key {
                    "remarks" => name = decoded_value,
                    "obfsparam" => obfs_param = Some(decoded_value),
                    "protoparam" => protocol_param = Some(decoded_value),
                    "group" => group = Some(decoded_value),
                    _ => {}
                }
            }
        }
    }

    Ok(Node::Ssr(SsrNode {
        name,
        server,
        port,
        cipher: method,
        password,
        protocol,
        protocol_param,
        obfs,
        obfs_param,
        group,
    }))
}

// ============================================================================
// Trojan Parser
// ============================================================================

fn parse_trojan(link: &str) -> Result<Node> {
    let url = Url::parse(link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let password = url.username().to_string();
    if password.is_empty() {
        return Err(ConvertError::MissingField {
            field: "password".into(),
            context: "Trojan URL".into(),
        });
    }

    let server = url.host_str()
        .ok_or_else(|| ConvertError::MissingField {
            field: "server".into(),
            context: "Trojan URL".into(),
        })?
        .to_string();

    let port = url.port().unwrap_or(443);
    let name = url_decode(url.fragment().unwrap_or(&server));

    let params: IndexMap<String, String> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Helper to get non-empty string parameter
    let get_param = |key: &str| -> Option<String> {
        params.get(key).filter(|v| !v.is_empty()).cloned()
    };

    let network = get_param("type");

    // Parse alpn - filter out empty strings
    let alpn = get_param("alpn").and_then(|v| {
        let list: Vec<String> = v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if list.is_empty() { None } else { Some(list) }
    });

    let mut node = TrojanNode {
        name,
        server,
        port,
        password: url_decode(&password),
        sni: get_param("sni"),
        skip_cert_verify: params.get("allowInsecure").map(|v| v == "1" || v == "true"),
        alpn,
        network: network.clone(),
        ws_opts: None,
        grpc_opts: None,
        client_fingerprint: get_param("fp"),
    };

    // Network-specific options
    if let Some(ref net) = network {
        match net.as_str() {
            "ws" => {
                let mut headers = IndexMap::new();
                if let Some(host) = get_param("host") {
                    headers.insert("Host".to_string(), host);
                }
                node.ws_opts = Some(WsOpts {
                    path: get_param("path"),
                    headers: if headers.is_empty() { None } else { Some(headers) },
                });
            }
            "grpc" => {
                node.grpc_opts = Some(GrpcOpts {
                    grpc_service_name: get_param("serviceName"),
                });
            }
            _ => {}
        }
    }

    Ok(Node::Trojan(node))
}

// ============================================================================
// Hysteria2 Parser
// ============================================================================
// Hysteria (v1) Parser
// Format: hysteria://host:port?protocol=udp&auth=str&peer=sni&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=xxx#name
// ============================================================================

fn parse_hysteria(link: &str) -> Result<Node> {
    use crate::node::HysteriaNode;

    // Normalize protocol prefix
    let link = if let Some(stripped) = link.strip_prefix("hy://") {
        format!("hysteria://{}", stripped)
    } else {
        link.to_string()
    };

    let url = url::Url::parse(&link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let server = url.host_str()
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "hysteria".into(),
            reason: "Missing server".into(),
        })?.to_string();

    let port = url.port()
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "hysteria".into(),
            reason: "Missing port".into(),
        })?;

    let name = urlencoding::decode(url.fragment().unwrap_or(""))
        .unwrap_or_default()
        .to_string();
    let name = if name.is_empty() { format!("{}:{}", server, port) } else { name };

    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

    let get_param = |key: &str| -> Option<String> {
        params.get(key).map(|v| v.to_string()).filter(|v| !v.is_empty())
    };

    let auth_str = get_param("auth");
    let protocol = get_param("protocol");
    let obfs = get_param("obfs").or_else(|| get_param("obfsParam"));
    let sni = get_param("peer").or_else(|| get_param("sni"));
    let alpn = get_param("alpn").map(|a| {
        a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>()
    }).filter(|v| !v.is_empty());
    let skip_cert_verify = get_param("insecure").map(|v| v == "1" || v == "true");
    let fingerprint = get_param("pinSHA256");

    let up = get_param("upmbps").map(|v| format!("{} Mbps", v));
    let down = get_param("downmbps").map(|v| format!("{} Mbps", v));

    Ok(Node::Hysteria(HysteriaNode {
        name,
        server,
        port,
        auth_str,
        protocol,
        up,
        down,
        obfs,
        sni,
        skip_cert_verify,
        alpn,
        fingerprint,
    }))
}

// ============================================================================
// Hysteria2 Parser
// ============================================================================

fn parse_hysteria2(link: &str) -> Result<Node> {
    // Normalize protocol prefix
    let link = if link.starts_with("hy2://") {
        link.replacen("hy2://", "hysteria2://", 1)
    } else {
        link.to_string()
    };

    let url = Url::parse(&link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let password = url.username().to_string();
    if password.is_empty() {
        return Err(ConvertError::MissingField {
            field: "password".into(),
            context: "Hysteria2 URL".into(),
        });
    }

    let server = url.host_str()
        .ok_or_else(|| ConvertError::MissingField {
            field: "server".into(),
            context: "Hysteria2 URL".into(),
        })?
        .to_string();

    let port = url.port().unwrap_or(443);
    let name = url_decode(url.fragment().unwrap_or(&server));

    let params: IndexMap<String, String> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Helper to get non-empty string parameter
    let get_param = |key: &str| -> Option<String> {
        params.get(key).filter(|v| !v.is_empty()).cloned()
    };

    // Parse alpn - filter out empty strings
    let alpn = get_param("alpn").and_then(|v| {
        let list: Vec<String> = v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if list.is_empty() { None } else { Some(list) }
    });

    Ok(Node::Hysteria2(Hysteria2Node {
        name,
        server,
        port,
        password: url_decode(&password),
        ports: get_param("mport"),
        obfs: get_param("obfs"),
        obfs_password: get_param("obfs-password"),
        sni: get_param("sni"),
        skip_cert_verify: params.get("insecure").map(|v| v == "1" || v == "true"),
        alpn,
        fingerprint: get_param("pinSHA256"),
        up: get_param("up"),
        down: get_param("down"),
    }))
}

// ============================================================================
// TUIC Parser (V5 format: tuic://uuid:password@server:port?params#name)
// ============================================================================

fn parse_tuic(link: &str) -> Result<Node> {
    let url = Url::parse(link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let server = url.host_str()
        .ok_or_else(|| ConvertError::MissingField {
            field: "server".into(),
            context: "TUIC URL".into(),
        })?
        .to_string();

    let port = url.port().unwrap_or(443);
    let name = url_decode(url.fragment().unwrap_or(&server));

    let params: IndexMap<String, String> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let get_param = |key: &str| -> Option<String> {
        params.get(key).filter(|v| !v.is_empty()).cloned()
    };

    // TUIC V5: tuic://uuid:password@server:port
    let uuid_str = url.username().to_string();
    let password_str = url.password().map(url_decode).unwrap_or_default();

    let (uuid, password, token) = if !uuid_str.is_empty() {
        (Some(uuid_str), Some(password_str).filter(|s| !s.is_empty()), None)
    } else {
        // TUIC V4: might use token
        (None, None, get_param("token"))
    };

    let alpn = get_param("alpn").and_then(|v| {
        let list: Vec<String> = v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if list.is_empty() { None } else { Some(list) }
    });

    Ok(Node::Tuic(TuicNode {
        name,
        server,
        port,
        token,
        uuid,
        password,
        sni: get_param("sni"),
        skip_cert_verify: params.get("allowInsecure")
            .or(params.get("insecure"))
            .map(|v| v == "1" || v == "true"),
        alpn,
        disable_sni: params.get("disable_sni").map(|v| v == "1" || v == "true"),
        reduce_rtt: params.get("reduce_rtt").map(|v| v == "1" || v == "true"),
        udp_relay_mode: get_param("udp_relay_mode").or_else(|| get_param("udp-relay-mode")),
        congestion_controller: get_param("congestion_control").or_else(|| get_param("congestion-controller")),
    }))
}

// ============================================================================
// WireGuard Parser
// Format: wg://[server]:port/?pk=[private_key]&local_address=10.0.0.2/24&peer_pk=[peer_public_key]&pre_shared_key=[psk]&mtu=[mtu]&reserved=0,0,0#name
// Also supports: wireguard://
// ============================================================================

fn parse_wireguard(link: &str) -> Result<Node> {
    use crate::node::WireGuardNode;

    // Normalize protocol prefix
    let link = if let Some(stripped) = link.strip_prefix("wg://") {
        format!("wireguard://{}", stripped)
    } else {
        link.to_string()
    };

    let url = url::Url::parse(&link).map_err(|e| ConvertError::UrlParseError(e.to_string()))?;

    let server = url.host_str()
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "wireguard".into(),
            reason: "Missing server".into(),
        })?.to_string();

    let port = url.port().unwrap_or(51820); // Default WireGuard port

    let name = urlencoding::decode(url.fragment().unwrap_or(""))
        .unwrap_or_default()
        .to_string();
    let name = if name.is_empty() { format!("WG-{}:{}", server, port) } else { name };

    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

    let get_param = |key: &str| -> Option<String> {
        params.get(key).map(|v| v.to_string()).filter(|v| !v.is_empty())
    };

    // Required: private key and public key
    let private_key = get_param("pk")
        .or_else(|| get_param("private_key"))
        .or_else(|| get_param("privatekey"))
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "wireguard".into(),
            reason: "Missing private key (pk)".into(),
        })?;

    let public_key = get_param("peer_pk")
        .or_else(|| get_param("peer_public_key"))
        .or_else(|| get_param("publickey"))
        .or_else(|| get_param("public_key"))
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "wireguard".into(),
            reason: "Missing peer public key (peer_pk)".into(),
        })?;

    // Local address (IP assigned to client)
    let local_address = get_param("local_address")
        .or_else(|| get_param("address"))
        .or_else(|| get_param("ip"));

    // Split local_address into IPv4 and IPv6 if needed
    let (ip, ipv6) = if let Some(addr) = local_address {
        // Could be comma-separated: "10.0.0.2/24,fd00::2/64"
        let parts: Vec<&str> = addr.split(',').collect();
        let mut ip4 = None;
        let mut ip6 = None;
        for part in parts {
            let part = part.trim();
            if part.contains(':') {
                ip6 = Some(part.to_string());
            } else if !part.is_empty() {
                ip4 = Some(part.to_string());
            }
        }
        (ip4, ip6)
    } else {
        (None, None)
    };

    let pre_shared_key = get_param("pre_shared_key")
        .or_else(|| get_param("psk"));

    // Reserved bytes (e.g., "0,0,0" or "209,98,59")
    let reserved = get_param("reserved").map(|s| {
        s.split(',')
            .filter_map(|v| v.trim().parse::<u16>().ok())
            .collect::<Vec<_>>()
    }).filter(|v| !v.is_empty());

    let mtu = get_param("mtu").and_then(|v| v.parse::<u32>().ok());

    // DNS servers
    let dns = get_param("dns").map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
    }).filter(|v| !v.is_empty());

    Ok(Node::WireGuard(WireGuardNode {
        name,
        server,
        port,
        private_key,
        public_key,
        ip,
        ipv6,
        pre_shared_key,
        reserved,
        mtu,
        dns,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn url_decode(s: &str) -> String {
    urlencoding::decode(s)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses [::1]:port
    if s.starts_with('[') {
        if let Some(bracket_idx) = s.find(']') {
            let host = &s[1..bracket_idx];
            let port_str = &s[bracket_idx + 1..];
            let port: u16 = port_str.trim_start_matches(':').parse()
                .map_err(|_| ConvertError::InvalidNodeFormat {
                    protocol: "ss".into(),
                    reason: format!("Invalid port: {}", port_str),
                })?;
            return Ok((host.to_string(), port));
        }
    }

    // Handle regular host:port
    let (host, port_str) = s.rsplit_once(':')
        .ok_or_else(|| ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: "Missing port".into(),
        })?;

    let port: u16 = port_str.parse()
        .map_err(|_| ConvertError::InvalidNodeFormat {
            protocol: "ss".into(),
            reason: format!("Invalid port: {}", port_str),
        })?;

    Ok((host.to_string(), port))
}
