//! Universal node parser supporting multiple proxy protocols
//! Parses VLESS, VMess, Shadowsocks, Trojan, Hysteria2 URLs

use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine as _};
use indexmap::IndexMap;
use url::Url;

use crate::error::{ConvertError, Result};
use crate::node::*;

/// Parse subscription content (supports mixed links and base64 encoded content)
pub fn parse_subscription_content(content: &str) -> Result<Vec<Node>> {
    let content = content.trim();

    // Try to decode as base64 first
    let decoded = if looks_like_base64(content) {
        match decode_base64_flexible(content) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => content.to_string(),
        }
    } else {
        content.to_string()
    };

    let mut nodes = Vec::new();

    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_single_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => {
                // Log but continue parsing other nodes
                eprintln!("Warning: Failed to parse link: {} - {}", line, e);
            }
        }
    }

    Ok(nodes)
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
    } else if link.starts_with("trojan://") {
        parse_trojan(link)
    } else if link.starts_with("hysteria2://") || link.starts_with("hy2://") {
        parse_hysteria2(link)
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

    let network = params.get("type").cloned().unwrap_or_else(|| "tcp".to_string());
    let security = params.get("security").cloned().unwrap_or_else(|| "none".to_string());

    let mut node = VlessNode {
        name,
        server,
        port,
        uuid,
        flow: params.get("flow").cloned(),
        network: network.clone(),
        tls: Some(security == "tls" || security == "reality"),
        servername: params.get("sni").cloned(),
        skip_cert_verify: params.get("allowInsecure").map(|v| v == "1" || v == "true"),
        // fp param = uTLS client fingerprint, NOT certificate fingerprint
        client_fingerprint: params.get("fp").cloned(),
        alpn: params.get("alpn").map(|v| v.split(',').map(|s| s.to_string()).collect()),
        reality_opts: None,
        ws_opts: None,
        grpc_opts: None,
        h2_opts: None,
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
            if let Some(host) = params.get("host") {
                headers.insert("Host".to_string(), host.clone());
            }
            node.ws_opts = Some(WsOpts {
                path: params.get("path").cloned(),
                headers: if headers.is_empty() { None } else { Some(headers) },
            });
        }
        "grpc" => {
            node.grpc_opts = Some(GrpcOpts {
                grpc_service_name: params.get("serviceName").cloned(),
            });
        }
        "h2" => {
            node.h2_opts = Some(H2Opts {
                path: params.get("path").cloned(),
                host: params.get("host").map(|v| v.split(',').map(|s| s.to_string()).collect()),
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
            if v.is_string() {
                v.as_str().map(|s| s.to_string())
            } else {
                Some(v.to_string().trim_matches('"').to_string())
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

    let port = get_u32("port")
        .ok_or_else(|| ConvertError::MissingField {
            field: "port".into(),
            context: "VMess config".into(),
        })? as u16;

    let uuid = get_str("id")
        .ok_or_else(|| ConvertError::MissingField {
            field: "id (uuid)".into(),
            context: "VMess config".into(),
        })?;

    let name = get_str("ps").unwrap_or_else(|| server.clone());
    let network = get_str("net").unwrap_or_else(|| "tcp".to_string());
    // tls field: "tls" means true, empty string or missing means false
    let tls = get_str("tls").map(|v| !v.is_empty() && v == "tls");

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
            node.h2_opts = Some(H2Opts {
                path: get_str("path"),
                host: get_str("host").map(|v| vec![v]),
            });
        }
        "grpc" => {
            node.grpc_opts = Some(GrpcOpts {
                grpc_service_name: get_str("path"),
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
    // SS URLs can be in two formats:
    // 1. ss://BASE64(method:password)@host:port#name
    // 2. ss://BASE64(method:password@host:port)#name (SIP002)

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

    // Try format 1: BASE64@host:port
    if let Some(at_idx) = link.rfind('@') {
        let encoded = &link[..at_idx];
        let server_port = &link[at_idx + 1..];

        // Decode method:password
        let decoded = decode_base64_flexible(encoded)?;
        let decoded_str = String::from_utf8_lossy(&decoded);

        let (cipher, password) = decoded_str.split_once(':')
            .ok_or_else(|| ConvertError::InvalidNodeFormat {
                protocol: "ss".into(),
                reason: "Invalid method:password format".into(),
            })?;

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
            plugin: None,
            plugin_opts: None,
        }));
    }

    // Try format 2: full base64
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

    let (server, port) = parse_host_port(server_port)?;
    let name = if name.is_empty() { server.clone() } else { name };

    Ok(Node::Shadowsocks(ShadowsocksNode {
        name,
        server,
        port,
        cipher: cipher.to_string(),
        password: password.to_string(),
        udp: Some(true),
        plugin: None,
        plugin_opts: None,
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

    let network = params.get("type").cloned();

    let mut node = TrojanNode {
        name,
        server,
        port,
        password: url_decode(&password),
        sni: params.get("sni").cloned(),
        skip_cert_verify: params.get("allowInsecure").map(|v| v == "1" || v == "true"),
        alpn: params.get("alpn").map(|v| v.split(',').map(|s| s.to_string()).collect()),
        network: network.clone(),
        ws_opts: None,
        grpc_opts: None,
        client_fingerprint: params.get("fp").cloned(),
    };

    // Network-specific options
    if let Some(ref net) = network {
        match net.as_str() {
            "ws" => {
                let mut headers = IndexMap::new();
                if let Some(host) = params.get("host") {
                    headers.insert("Host".to_string(), host.clone());
                }
                node.ws_opts = Some(WsOpts {
                    path: params.get("path").cloned(),
                    headers: if headers.is_empty() { None } else { Some(headers) },
                });
            }
            "grpc" => {
                node.grpc_opts = Some(GrpcOpts {
                    grpc_service_name: params.get("serviceName").cloned(),
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

    Ok(Node::Hysteria2(Hysteria2Node {
        name,
        server,
        port,
        password: url_decode(&password),
        obfs: params.get("obfs").cloned(),
        obfs_password: params.get("obfs-password").cloned(),
        sni: params.get("sni").cloned(),
        skip_cert_verify: params.get("insecure").map(|v| v == "1" || v == "true"),
        alpn: params.get("alpn").map(|v| v.split(',').map(|s| s.to_string()).collect()),
        fingerprint: params.get("pinSHA256").cloned(),
        up: params.get("up").cloned(),
        down: params.get("down").cloned(),
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
