//! Node definitions for various proxy protocols
//! Supports: VLESS, VMess, Shadowsocks, Trojan, Hysteria2

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Unified node enum supporting all major proxy protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Node {
    Vless(VlessNode),
    Vmess(VmessNode),
    #[serde(rename = "ss")]
    Shadowsocks(ShadowsocksNode),
    Trojan(TrojanNode),
    Hysteria2(Hysteria2Node),
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::Vless(n) => &n.name,
            Node::Vmess(n) => &n.name,
            Node::Shadowsocks(n) => &n.name,
            Node::Trojan(n) => &n.name,
            Node::Hysteria2(n) => &n.name,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Node::Vless(n) => n.name = name,
            Node::Vmess(n) => n.name = name,
            Node::Shadowsocks(n) => n.name = name,
            Node::Trojan(n) => n.name = name,
            Node::Hysteria2(n) => n.name = name,
        }
    }

    pub fn to_clash_proxy(&self) -> IndexMap<String, serde_yaml::Value> {
        match self {
            Node::Vless(n) => n.to_clash_map(),
            Node::Vmess(n) => n.to_clash_map(),
            Node::Shadowsocks(n) => n.to_clash_map(),
            Node::Trojan(n) => n.to_clash_map(),
            Node::Hysteria2(n) => n.to_clash_map(),
        }
    }

    /// Generate a deduplication key based on protocol, server, port, and credential.
    /// Two nodes with the same dedup_key are considered duplicates.
    pub fn dedup_key(&self) -> String {
        match self {
            Node::Vless(n) => format!("vless:{}:{}:{}", n.server, n.port, n.uuid),
            Node::Vmess(n) => format!("vmess:{}:{}:{}", n.server, n.port, n.uuid),
            Node::Shadowsocks(n) => format!("ss:{}:{}:{}:{}", n.server, n.port, n.cipher, n.password),
            Node::Trojan(n) => format!("trojan:{}:{}:{}", n.server, n.port, n.password),
            Node::Hysteria2(n) => format!("hy2:{}:{}:{}", n.server, n.port, n.password),
        }
    }
}

// ============================================================================
// VLESS Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_opts: Option<RealityOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<WsOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<H2Opts>,
    /// uTLS client fingerprint (chrome, firefox, safari, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
}

impl VlessNode {
    /// Convert to Clash YAML map with correct field order for VLESS Reality
    /// Order matters! Mihomo requires: name, type, server, port, uuid, udp, tls, network, flow, servername, reality-opts, client-fingerprint
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();

        // 1. Basic fields (fixed order)
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("vless"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("uuid".into(), v_str(&self.uuid));
        map.insert("udp".into(), v_bool(true));

        // 2. TLS must come before flow!
        map.insert("tls".into(), v_bool(self.tls.unwrap_or(false)));

        // 3. Network
        map.insert("network".into(), v_str(&self.network));

        // 4. Flow comes after tls and network
        if let Some(flow) = &self.flow {
            if !flow.is_empty() {
                map.insert("flow".into(), v_str(flow));
            }
        }

        // 5. Servername (SNI)
        if let Some(sni) = &self.servername {
            if !sni.is_empty() {
                map.insert("servername".into(), v_str(sni));
            }
        }

        // 6. Skip cert verify (if present)
        if let Some(skip) = self.skip_cert_verify {
            map.insert("skip-cert-verify".into(), v_bool(skip));
        }

        // 7. ALPN (if present)
        if let Some(alpn) = &self.alpn {
            if !alpn.is_empty() {
                map.insert("alpn".into(), v_str_seq(alpn));
            }
        }

        // 8. Reality-opts must come before client-fingerprint!
        if let Some(reality) = &self.reality_opts {
            let mut m = serde_yaml::Mapping::new();
            m.insert(v_key("public-key"), v_str(&reality.public_key));
            if let Some(sid) = &reality.short_id {
                if !sid.is_empty() {
                    m.insert(v_key("short-id"), v_str(sid));
                }
            }
            map.insert("reality-opts".into(), serde_yaml::Value::Mapping(m));
        }

        // 9. Client-fingerprint comes LAST (after reality-opts)
        if let Some(cfp) = &self.client_fingerprint {
            if !cfp.is_empty() {
                map.insert("client-fingerprint".into(), v_str(cfp));
            }
        }

        // 10. Network-specific options (ws-opts, grpc-opts, h2-opts)
        insert_transport_opts(&mut map, &self.network, &self.ws_opts, &self.grpc_opts, &self.h2_opts);

        map
    }
}

// ============================================================================
// VMess Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct VmessNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(rename = "alterId")]
    pub alterId: u32,
    pub cipher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<WsOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<H2Opts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<GrpcOpts>,
}

impl VmessNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("vmess"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("uuid".into(), v_str(&self.uuid));
        map.insert("alterId".into(), serde_yaml::Value::Number(self.alterId.into()));
        map.insert("cipher".into(), v_str(&self.cipher));
        map.insert("udp".into(), v_bool(true));

        if let Some(tls) = self.tls {
            map.insert("tls".into(), v_bool(tls));
        }

        if let Some(network) = &self.network {
            map.insert("network".into(), v_str(network));
        }

        if let Some(skip) = self.skip_cert_verify {
            map.insert("skip-cert-verify".into(), v_bool(skip));
        }

        if let Some(sni) = &self.servername {
            if !sni.is_empty() {
                map.insert("servername".into(), v_str(sni));
            }
        }

        let network = self.network.as_deref().unwrap_or("tcp");
        insert_transport_opts(&mut map, network, &self.ws_opts, &self.grpc_opts, &self.h2_opts);

        map
    }
}

// ============================================================================
// Shadowsocks Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<IndexMap<String, String>>,
}

impl ShadowsocksNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("ss"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("cipher".into(), v_str(&self.cipher));
        map.insert("password".into(), v_str(&self.password));
        map.insert("udp".into(), v_bool(self.udp.unwrap_or(true)));

        if let Some(plugin) = &self.plugin {
            map.insert("plugin".into(), v_str(plugin));
            if let Some(opts) = &self.plugin_opts {
                let mut opts_map = serde_yaml::Mapping::new();
                for (k, v) in opts {
                    opts_map.insert(v_key(k), v_str(v));
                }
                map.insert("plugin-opts".into(), serde_yaml::Value::Mapping(opts_map));
            }
        }

        map
    }
}

// ============================================================================
// Trojan Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<WsOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<GrpcOpts>,
    /// uTLS client fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
}

impl TrojanNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("trojan"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("password".into(), v_str(&self.password));
        map.insert("udp".into(), v_bool(true));

        if let Some(sni) = &self.sni {
            if !sni.is_empty() {
                map.insert("sni".into(), v_str(sni));
            }
        }

        if let Some(skip) = self.skip_cert_verify {
            map.insert("skip-cert-verify".into(), v_bool(skip));
        }

        if let Some(alpn) = &self.alpn {
            if !alpn.is_empty() {
                map.insert("alpn".into(), v_str_seq(alpn));
            }
        }

        if let Some(cfp) = &self.client_fingerprint {
            if !cfp.is_empty() {
                map.insert("client-fingerprint".into(), v_str(cfp));
            }
        }

        if let Some(network) = &self.network {
            map.insert("network".into(), v_str(network));
            insert_transport_opts(&mut map, network, &self.ws_opts, &self.grpc_opts, &None);
        }

        map
    }
}

// ============================================================================
// Hysteria2 Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Node {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
}

impl Hysteria2Node {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("hysteria2"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("password".into(), v_str(&self.password));

        if let Some(obfs) = &self.obfs {
            map.insert("obfs".into(), v_str(obfs));
        }
        if let Some(obfs_pass) = &self.obfs_password {
            map.insert("obfs-password".into(), v_str(obfs_pass));
        }
        if let Some(sni) = &self.sni {
            if !sni.is_empty() {
                map.insert("sni".into(), v_str(sni));
            }
        }
        if let Some(skip) = self.skip_cert_verify {
            map.insert("skip-cert-verify".into(), v_bool(skip));
        }
        if let Some(alpn) = &self.alpn {
            if !alpn.is_empty() {
                map.insert("alpn".into(), v_str_seq(alpn));
            }
        }
        if let Some(fp) = &self.fingerprint {
            if !fp.is_empty() {
                map.insert("fingerprint".into(), v_str(fp));
            }
        }
        if let Some(up) = &self.up {
            map.insert("up".into(), v_str(up));
        }
        if let Some(down) = &self.down {
            map.insert("down".into(), v_str(down));
        }

        map
    }
}

// ============================================================================
// Common Options Structs
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityOpts {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsOpts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<IndexMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcOpts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Opts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
}

// ============================================================================
// YAML helpers (reduce boilerplate)
// ============================================================================

fn v_str(s: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(s.to_string())
}

fn v_key(s: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(s.to_string())
}

fn v_bool(b: bool) -> serde_yaml::Value {
    serde_yaml::Value::Bool(b)
}

fn v_num(n: u16) -> serde_yaml::Value {
    serde_yaml::Value::Number(n.into())
}

fn v_str_seq(items: &[String]) -> serde_yaml::Value {
    serde_yaml::Value::Sequence(
        items.iter().map(|s| serde_yaml::Value::String(s.clone())).collect()
    )
}

/// Insert transport options (ws-opts, grpc-opts, h2-opts) based on network type
fn insert_transport_opts(
    map: &mut IndexMap<String, serde_yaml::Value>,
    network: &str,
    ws_opts: &Option<WsOpts>,
    grpc_opts: &Option<GrpcOpts>,
    h2_opts: &Option<H2Opts>,
) {
    match network {
        "ws" => {
            if let Some(ws) = ws_opts {
                let mut m = serde_yaml::Mapping::new();
                if let Some(path) = &ws.path {
                    m.insert(v_key("path"), v_str(path));
                }
                if let Some(headers) = &ws.headers {
                    let mut hm = serde_yaml::Mapping::new();
                    for (k, v) in headers {
                        hm.insert(v_key(k), v_str(v));
                    }
                    m.insert(v_key("headers"), serde_yaml::Value::Mapping(hm));
                }
                if !m.is_empty() {
                    map.insert("ws-opts".into(), serde_yaml::Value::Mapping(m));
                }
            }
        }
        "grpc" => {
            if let Some(grpc) = grpc_opts {
                let mut m = serde_yaml::Mapping::new();
                if let Some(sn) = &grpc.grpc_service_name {
                    m.insert(v_key("grpc-service-name"), v_str(sn));
                }
                if !m.is_empty() {
                    map.insert("grpc-opts".into(), serde_yaml::Value::Mapping(m));
                }
            }
        }
        "h2" => {
            if let Some(h2) = h2_opts {
                let mut m = serde_yaml::Mapping::new();
                if let Some(path) = &h2.path {
                    m.insert(v_key("path"), v_str(path));
                }
                if let Some(host) = &h2.host {
                    m.insert(v_key("host"), v_str_seq(host));
                }
                if !m.is_empty() {
                    map.insert("h2-opts".into(), serde_yaml::Value::Mapping(m));
                }
            }
        }
        _ => {}
    }
}
