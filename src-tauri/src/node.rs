//! Node definitions for various proxy protocols
//! Supports: VLESS, VMess, Shadowsocks, ShadowsocksR, Trojan, Hysteria2, TUIC

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
    #[serde(rename = "ssr")]
    Ssr(SsrNode),
    Trojan(TrojanNode),
    #[serde(rename = "hysteria")]
    Hysteria(HysteriaNode),
    Hysteria2(Hysteria2Node),
    Tuic(TuicNode),
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardNode),
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::Vless(n) => &n.name,
            Node::Vmess(n) => &n.name,
            Node::Shadowsocks(n) => &n.name,
            Node::Ssr(n) => &n.name,
            Node::Trojan(n) => &n.name,
            Node::Hysteria(n) => &n.name,
            Node::Hysteria2(n) => &n.name,
            Node::Tuic(n) => &n.name,
            Node::WireGuard(n) => &n.name,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Node::Vless(n) => n.name = name,
            Node::Vmess(n) => n.name = name,
            Node::Shadowsocks(n) => n.name = name,
            Node::Ssr(n) => n.name = name,
            Node::Trojan(n) => n.name = name,
            Node::Hysteria(n) => n.name = name,
            Node::Hysteria2(n) => n.name = name,
            Node::Tuic(n) => n.name = name,
            Node::WireGuard(n) => n.name = name,
        }
    }

    pub fn to_clash_proxy(&self) -> IndexMap<String, serde_yaml::Value> {
        match self {
            Node::Vless(n) => n.to_clash_map(),
            Node::Vmess(n) => n.to_clash_map(),
            Node::Shadowsocks(n) => n.to_clash_map(),
            Node::Ssr(n) => n.to_clash_map(),
            Node::Trojan(n) => n.to_clash_map(),
            Node::Hysteria(n) => n.to_clash_map(),
            Node::Hysteria2(n) => n.to_clash_map(),
            Node::Tuic(n) => n.to_clash_map(),
            Node::WireGuard(n) => n.to_clash_map(),
        }
    }

    /// Generate a deduplication key based on protocol, server, port, and credential.
    pub fn dedup_key(&self) -> String {
        match self {
            Node::Vless(n) => format!("vless:{}:{}:{}", n.server, n.port, n.uuid),
            Node::Vmess(n) => format!("vmess:{}:{}:{}", n.server, n.port, n.uuid),
            Node::Shadowsocks(n) => format!("ss:{}:{}:{}:{}", n.server, n.port, n.cipher, n.password),
            Node::Ssr(n) => format!("ssr:{}:{}:{}:{}:{}", n.server, n.port, n.cipher, n.password, n.protocol),
            Node::Trojan(n) => format!("trojan:{}:{}:{}", n.server, n.port, n.password),
            Node::Hysteria(n) => format!("hy:{}:{}:{}", n.server, n.port, n.auth_str.as_deref().unwrap_or("")),
            Node::Hysteria2(n) => format!("hy2:{}:{}:{}", n.server, n.port, n.password),
            Node::Tuic(n) => format!("tuic:{}:{}:{}", n.server, n.port, n.uuid.as_deref().or(n.token.as_deref()).unwrap_or("")),
            Node::WireGuard(n) => format!("wg:{}:{}:{}", n.server, n.port, n.public_key),
        }
    }

    /// Protocol type string for display
    pub fn protocol_type(&self) -> &str {
        match self {
            Node::Vless(_) => "VLESS",
            Node::Vmess(_) => "VMess",
            Node::Shadowsocks(_) => "SS",
            Node::Ssr(_) => "SSR",
            Node::Trojan(_) => "Trojan",
            Node::Hysteria(_) => "Hysteria",
            Node::Hysteria2(_) => "Hysteria2",
            Node::Tuic(_) => "TUIC",
            Node::WireGuard(_) => "WireGuard",
        }
    }

    /// Server address for display
    pub fn server(&self) -> &str {
        match self {
            Node::Vless(n) => &n.server,
            Node::Vmess(n) => &n.server,
            Node::Shadowsocks(n) => &n.server,
            Node::Ssr(n) => &n.server,
            Node::Trojan(n) => &n.server,
            Node::Hysteria(n) => &n.server,
            Node::Hysteria2(n) => &n.server,
            Node::Tuic(n) => &n.server,
            Node::WireGuard(n) => &n.server,
        }
    }

    /// Port for display
    pub fn port(&self) -> u16 {
        match self {
            Node::Vless(n) => n.port,
            Node::Vmess(n) => n.port,
            Node::Shadowsocks(n) => n.port,
            Node::Ssr(n) => n.port,
            Node::Trojan(n) => n.port,
            Node::Hysteria(n) => n.port,
            Node::Hysteria2(n) => n.port,
            Node::Tuic(n) => n.port,
            Node::WireGuard(n) => n.port,
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
    /// UDP packet encoding: xudp (xray) or packetaddr (v2ray 5+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
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

        // 4b. Packet encoding (xudp for xray, packetaddr for v2ray 5+)
        if let Some(pe) = &self.packet_encoding {
            if !pe.is_empty() {
                map.insert("packet-encoding".into(), v_str(pe));
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
                    // Boolean fields should be converted from string to bool
                    if k == "tls" || k == "mux" || k == "skip-cert-verify" {
                        let bool_val = v == "true" || v == "1";
                        opts_map.insert(v_key(k), v_bool(bool_val));
                    } else {
                        opts_map.insert(v_key(k), v_str(v));
                    }
                }
                map.insert("plugin-opts".into(), serde_yaml::Value::Mapping(opts_map));
            }
        }

        map
    }
}

// ============================================================================
// ShadowsocksR (SSR) Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,        // method (e.g., aes-256-cfb)
    pub password: String,
    pub protocol: String,      // e.g., "auth_aes128_sha1", "origin"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_param: Option<String>,
    pub obfs: String,          // e.g., "tls1.2_ticket_auth", "plain"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl SsrNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("ssr"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("cipher".into(), v_str(&self.cipher));
        map.insert("password".into(), v_str(&self.password));
        map.insert("protocol".into(), v_str(&self.protocol));
        map.insert("obfs".into(), v_str(&self.obfs));
        map.insert("udp".into(), v_bool(true));

        if let Some(protocol_param) = &self.protocol_param {
            if !protocol_param.is_empty() {
                map.insert("protocol-param".into(), v_str(protocol_param));
            }
        }

        if let Some(obfs_param) = &self.obfs_param {
            if !obfs_param.is_empty() {
                map.insert("obfs-param".into(), v_str(obfs_param));
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
// Hysteria (v1) Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HysteriaNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_str: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl HysteriaNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("hysteria"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));

        if let Some(auth) = &self.auth_str {
            map.insert("auth-str".into(), v_str(auth));
        }
        if let Some(protocol) = &self.protocol {
            if !protocol.is_empty() {
                map.insert("protocol".into(), v_str(protocol));
            }
        }
        if let Some(up) = &self.up {
            map.insert("up".into(), v_str(up));
        }
        if let Some(down) = &self.down {
            map.insert("down".into(), v_str(down));
        }
        if let Some(obfs) = &self.obfs {
            if !obfs.is_empty() {
                map.insert("obfs".into(), v_str(obfs));
            }
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
    /// Port range for port hopping (e.g., "443-8443")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
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
        if let Some(ports) = &self.ports {
            if !ports.is_empty() {
                map.insert("ports".into(), v_str(ports));
            }
        }
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
// TUIC Node (V4/V5)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// TUIC V4 token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// TUIC V5 uuid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// TUIC V5 password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sni: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_rtt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_controller: Option<String>,
}

impl TuicNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("tuic"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));

        if let Some(token) = &self.token {
            map.insert("token".into(), v_str(token));
        }
        if let Some(uuid) = &self.uuid {
            map.insert("uuid".into(), v_str(uuid));
        }
        if let Some(password) = &self.password {
            map.insert("password".into(), v_str(password));
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
        if let Some(disable_sni) = self.disable_sni {
            map.insert("disable-sni".into(), v_bool(disable_sni));
        }
        if let Some(reduce_rtt) = self.reduce_rtt {
            map.insert("reduce-rtt".into(), v_bool(reduce_rtt));
        }
        if let Some(mode) = &self.udp_relay_mode {
            map.insert("udp-relay-mode".into(), v_str(mode));
        }
        if let Some(cc) = &self.congestion_controller {
            map.insert("congestion-controller".into(), v_str(cc));
        }

        map
    }
}

// ============================================================================
// WireGuard Node
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// Client private key (base64)
    pub private_key: String,
    /// Server public key (base64)
    pub public_key: String,
    /// Client IPv4 address in WireGuard network
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Client IPv6 address in WireGuard network
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    /// Allowed IPs (traffic selectors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// Pre-shared key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    /// Reserved bytes (e.g., for WARP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Vec<u16>>,
    /// MTU
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// DNS servers for remote resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
}

impl WireGuardNode {
    pub fn to_clash_map(&self) -> IndexMap<String, serde_yaml::Value> {
        let mut map = IndexMap::new();
        map.insert("name".into(), v_str(&self.name));
        map.insert("type".into(), v_str("wireguard"));
        map.insert("server".into(), v_str(&self.server));
        map.insert("port".into(), v_num(self.port));
        map.insert("private-key".into(), v_str(&self.private_key));
        map.insert("public-key".into(), v_str(&self.public_key));

        if let Some(ip) = &self.ip {
            if !ip.is_empty() {
                // Strip CIDR notation for mihomo (e.g., "172.16.0.2/32" -> "172.16.0.2")
                let ip_clean = ip.split('/').next().unwrap_or(ip);
                map.insert("ip".into(), v_str(ip_clean));
            }
        }
        if let Some(ipv6) = &self.ipv6 {
            if !ipv6.is_empty() {
                let ipv6_clean = ipv6.split('/').next().unwrap_or(ipv6);
                map.insert("ipv6".into(), v_str(ipv6_clean));
            }
        }
        if let Some(psk) = &self.pre_shared_key {
            if !psk.is_empty() {
                map.insert("pre-shared-key".into(), v_str(psk));
            }
        }
        if let Some(reserved) = &self.reserved {
            if !reserved.is_empty() {
                let seq: Vec<serde_yaml::Value> = reserved.iter()
                    .map(|v| serde_yaml::Value::Number((*v).into()))
                    .collect();
                map.insert("reserved".into(), serde_yaml::Value::Sequence(seq));
            }
        }

        map.insert("udp".into(), v_bool(true));

        if let Some(mtu) = self.mtu {
            map.insert("mtu".into(), serde_yaml::Value::Number(mtu.into()));
        }

        // Remote DNS resolution
        if let Some(dns) = &self.dns {
            if !dns.is_empty() {
                map.insert("remote-dns-resolve".into(), v_bool(true));
                map.insert("dns".into(), v_str_seq(dns));
            }
        }

        if let Some(allowed_ips) = &self.allowed_ips {
            if !allowed_ips.is_empty() {
                map.insert("allowed-ips".into(), v_str_seq(allowed_ips));
            }
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

// ============================================================================
// Cipher/Method Validation Constants (for reference and future validation)
// ============================================================================

/// Valid Shadowsocks ciphers supported by Clash/Mihomo
#[allow(dead_code)]
pub const SS_VALID_CIPHERS: &[&str] = &[
    // AEAD ciphers (recommended)
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    // AEAD 2022 ciphers (Mihomo)
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    // Legacy stream ciphers (deprecated but still supported)
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// Valid SSR ciphers
#[allow(dead_code)]
pub const SSR_VALID_CIPHERS: &[&str] = &[
    "none",
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
];

/// Valid SSR protocols
#[allow(dead_code)]
pub const SSR_VALID_PROTOCOLS: &[&str] = &[
    "origin",
    "verify_deflate",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
];

/// Valid SSR obfs methods
#[allow(dead_code)]
pub const SSR_VALID_OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

/// Normalize cipher name to standard format
#[allow(dead_code)]
pub fn normalize_cipher(cipher: &str) -> String {
    cipher.to_lowercase().replace('_', "-")
}

/// Check if a Shadowsocks cipher is valid
pub fn is_valid_ss_cipher(cipher: &str) -> bool {
    let normalized = normalize_cipher(cipher);
    SS_VALID_CIPHERS.contains(&normalized.as_str())
}

/// Check if an SSR cipher is valid
pub fn is_valid_ssr_cipher(cipher: &str) -> bool {
    let normalized = normalize_cipher(cipher);
    SSR_VALID_CIPHERS.contains(&normalized.as_str())
}
