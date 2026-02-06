//! INI configuration parser for ACL4SSR format
//! Converts INI config to Clash proxy groups and rules

use indexmap::IndexMap;
use ini::Ini;
use regex::Regex;

use crate::error::{ConvertError, Result};
use crate::node::Node;

/// Parsed proxy group from INI config
#[derive(Debug, Clone)]
pub struct ParsedProxyGroup {
    pub name: String,
    pub group_type: String,
    pub proxies: Vec<ProxyMatcher>,
    pub url: Option<String>,
    pub interval: Option<u32>,
    pub timeout: Option<u32>,
    pub tolerance: Option<u32>,
}

/// Matcher for proxies - can be a literal name, regex pattern, or special keyword
#[derive(Debug, Clone)]
pub enum ProxyMatcher {
    /// Literal proxy name
    Literal(String),
    /// Regex pattern to match proxy names
    Pattern(String),
    /// Special keyword like "[]DIRECT", "[]REJECT", etc.
    Special(String),
    /// Include all proxies matching a group (like `[]GroupName`)
    GroupRef(String),
}

/// Parsed rule from INI config
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub rule_type: String,
    pub value: String,
    pub target: String,
    pub no_resolve: bool,
}

/// Result of parsing an INI config file
#[derive(Debug)]
pub struct ParsedIniConfig {
    pub proxy_groups: Vec<ParsedProxyGroup>,
    pub rules: Vec<ParsedRule>,
    pub ruleset_urls: Vec<(String, String)>, // (target_group, url)
}

/// Parse ACL4SSR INI configuration
pub fn parse_ini_config(content: &str) -> Result<ParsedIniConfig> {
    let ini = Ini::load_from_str(content).map_err(|e| {
        ConvertError::IniParseError(e.to_string())
    })?;

    let mut proxy_groups = Vec::new();
    let mut rules = Vec::new();
    let mut ruleset_urls = Vec::new();

    // Parse [custom] section for proxy groups
    if let Some(custom) = ini.section(Some("custom")) {
        for (key, value) in custom.iter() {
            if key == "custom_proxy_group" {
                if let Some(group) = parse_proxy_group_line(value) {
                    proxy_groups.push(group);
                }
            } else if key == "ruleset" {
                if let Some((target, url_or_rule)) = parse_ruleset_line(value) {
                    // Check if it's an inline rule (starts with [])
                    if url_or_rule.starts_with("[]") {
                        let rule_content = url_or_rule.strip_prefix("[]").unwrap();
                        // Parse inline rule like "GEOIP,CN" or "FINAL"
                        if let Some(rule) = parse_inline_rule(rule_content, &target) {
                            rules.push(rule);
                        }
                    } else {
                        // It's a remote ruleset URL
                        ruleset_urls.push((target, url_or_rule));
                    }
                }
            }
        }
    }

    // Parse [Proxy Group] section (alternative format)
    if let Some(section) = ini.section(Some("Proxy Group")) {
        for (_, value) in section.iter() {
            if let Some(group) = parse_proxy_group_line(value) {
                proxy_groups.push(group);
            }
        }
    }

    // Parse [Rule] section
    if let Some(rule_section) = ini.section(Some("Rule")) {
        for (_, value) in rule_section.iter() {
            if let Some(rule) = parse_rule_line(value) {
                rules.push(rule);
            }
        }
    }

    // Parse [rules] section (alternative)
    if let Some(rule_section) = ini.section(Some("rules")) {
        for (_, value) in rule_section.iter() {
            if let Some(rule) = parse_rule_line(value) {
                rules.push(rule);
            }
        }
    }

    Ok(ParsedIniConfig {
        proxy_groups,
        rules,
        ruleset_urls,
    })
}

/// Parse a custom_proxy_group line
/// Format: GroupName`type`proxy1`proxy2`...`[test_url]`[interval[,timeout][,tolerance]]
/// Examples:
///   - 🚀节点选择`select`[]♻️自动选择`[]🎯全球直连`.*
///   - ♻️自动选择`url-test`.*`http://www.gstatic.com/generate_204`300,,50
///   - 📺Netflix`select`[]🚀节点选择`[]♻️自动选择`🇭🇰香港.*`🇸🇬新加坡.*
fn parse_proxy_group_line(line: &str) -> Option<ParsedProxyGroup> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // ACL4SSR uses backtick as delimiter
    let parts: Vec<&str> = line.split('`').collect();

    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].trim().to_string();
    let group_type = parts[1].trim().to_lowercase();

    let mut proxies = Vec::new();
    let mut url = None;
    let mut interval = None;
    let mut timeout = None;
    let mut tolerance = None;

    // For url-test, fallback, load-balance types, we need to parse from the end
    let needs_url_test = matches!(group_type.as_str(), "url-test" | "fallback" | "load-balance");

    // Collect all parts after type
    let proxy_parts: Vec<&str> = parts.iter().skip(2).map(|s| s.trim()).collect();

    if proxy_parts.is_empty() {
        return Some(ParsedProxyGroup {
            name,
            group_type,
            proxies,
            url,
            interval,
            timeout,
            tolerance,
        });
    }

    // For url-test/fallback/load-balance, parse from the end to find URL and interval params
    let mut proxy_end_idx = proxy_parts.len();

    if needs_url_test && !proxy_parts.is_empty() {
        // Check the last part for interval params (e.g., "300", "300,,50", "300,150,50")
        let last = proxy_parts[proxy_parts.len() - 1];
        if is_interval_param(last) {
            let (int, tout, tol) = parse_interval_param(last);
            interval = int;
            timeout = tout;
            tolerance = tol;
            proxy_end_idx -= 1;

            // Check if second-to-last is a URL
            if proxy_end_idx >= 1 {
                let second_last = proxy_parts[proxy_end_idx - 1];
                if second_last.starts_with("http://") || second_last.starts_with("https://") {
                    url = Some(second_last.to_string());
                    proxy_end_idx -= 1;
                }
            }
        } else if last.starts_with("http://") || last.starts_with("https://") {
            // Last part is URL, no interval params
            url = Some(last.to_string());
            proxy_end_idx -= 1;
        }
    }

    // Parse proxy matchers from the remaining parts
    for part in proxy_parts.iter().take(proxy_end_idx) {
        let part = *part;
        if part.is_empty() {
            continue;
        }

        let matcher = parse_proxy_matcher(part);
        proxies.push(matcher);
    }

    Some(ParsedProxyGroup {
        name,
        group_type,
        proxies,
        url,
        interval,
        timeout,
        tolerance,
    })
}

/// Check if a string looks like interval parameters (number or number,number,number format)
fn is_interval_param(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Check if it's a number or comma-separated numbers (like "300", "300,,50", "300,150,50")
    let parts: Vec<&str> = s.split(',').collect();
    // First part should be a number (interval)
    if let Some(first) = parts.first() {
        if first.parse::<u32>().is_ok() {
            return true;
        }
    }
    false
}

/// Parse interval parameters: "300" or "300,,50" or "300,150,50"
/// Format: interval[,timeout][,tolerance]
fn parse_interval_param(s: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    let parts: Vec<&str> = s.split(',').collect();
    let mut interval = None;
    let mut timeout = None;
    let mut tolerance = None;

    if let Some(p) = parts.first() {
        interval = p.parse().ok();
    }
    if parts.len() >= 2 {
        if let Some(p) = parts.get(1) {
            if !p.is_empty() {
                timeout = p.parse().ok();
            }
        }
    }
    if parts.len() >= 3 {
        if let Some(p) = parts.get(2) {
            if !p.is_empty() {
                tolerance = p.parse().ok();
            }
        }
    }

    (interval, timeout, tolerance)
}

/// Parse a single proxy matcher
fn parse_proxy_matcher(part: &str) -> ProxyMatcher {
    if part.starts_with("[]") {
        let inner = part.strip_prefix("[]").unwrap();
        if inner == "DIRECT" || inner == "REJECT" {
            ProxyMatcher::Special(inner.to_string())
        } else {
            ProxyMatcher::GroupRef(inner.to_string())
        }
    } else if is_regex_pattern(part) {
        ProxyMatcher::Pattern(part.to_string())
    } else {
        ProxyMatcher::Literal(part.to_string())
    }
}

/// Check if a string looks like a regex pattern
fn is_regex_pattern(s: &str) -> bool {
    // Common regex characters that indicate it's a pattern
    s.contains('*') || s.contains('^') || s.contains('$')
        || s.contains('(') || s.contains('[') || s.contains('|')
        || s.contains('+') || s.contains('?') || s.contains('\\')
        || s == ".*"
}

/// Parse a ruleset line
/// Format: target,url or target,[]inline_rule
fn parse_ruleset_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();

    // Find first comma to split target and url
    if let Some(idx) = line.find(',') {
        let target = line[..idx].trim().to_string();
        let url_or_rule = line[idx + 1..].trim().to_string();
        Some((target, url_or_rule))
    } else {
        None
    }
}

/// Parse an inline rule like "GEOIP,CN" or "FINAL"
fn parse_inline_rule(rule_content: &str, target: &str) -> Option<ParsedRule> {
    let rule_content = rule_content.trim();
    if rule_content.is_empty() {
        return None;
    }

    // Handle FINAL/MATCH rule
    if rule_content.eq_ignore_ascii_case("FINAL") || rule_content.eq_ignore_ascii_case("MATCH") {
        return Some(ParsedRule {
            rule_type: "MATCH".to_string(),
            value: String::new(),
            target: target.to_string(),
            no_resolve: false,
        });
    }

    // Handle rules with value like "GEOIP,CN"
    let parts: Vec<&str> = rule_content.split(',').collect();
    if parts.len() >= 2 {
        Some(ParsedRule {
            rule_type: parts[0].trim().to_uppercase(),
            value: parts[1].trim().to_string(),
            target: target.to_string(),
            no_resolve: parts.len() > 2 && parts[2].trim().eq_ignore_ascii_case("no-resolve"),
        })
    } else {
        // Single word rule type (shouldn't happen but handle gracefully)
        Some(ParsedRule {
            rule_type: rule_content.to_uppercase(),
            value: String::new(),
            target: target.to_string(),
            no_resolve: false,
        })
    }
}

/// Parse a rule line
fn parse_rule_line(line: &str) -> Option<ParsedRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 2 {
        return None;
    }

    let rule_type = parts[0].trim().to_uppercase();
    let no_resolve = line.to_uppercase().contains("NO-RESOLVE");

    // Handle MATCH/FINAL rules (only 2 parts)
    if rule_type == "MATCH" || rule_type == "FINAL" {
        return Some(ParsedRule {
            rule_type: "MATCH".to_string(),
            value: String::new(),
            target: parts[1].trim().to_string(),
            no_resolve: false,
        });
    }

    if parts.len() < 3 {
        return None;
    }

    Some(ParsedRule {
        rule_type,
        value: parts[1].trim().to_string(),
        target: parts[2].trim().to_string(),
        no_resolve,
    })
}

/// Resolve proxy matchers to actual proxy names
/// For Clash, group references should be kept as-is (not expanded)
pub fn resolve_proxy_group(
    group: &ParsedProxyGroup,
    nodes: &[Node],
    _all_group_names: &[String],
) -> Vec<String> {
    let mut result = Vec::new();

    for matcher in &group.proxies {
        match matcher {
            ProxyMatcher::Literal(name) => {
                result.push(name.clone());
            }
            ProxyMatcher::Pattern(pattern) => {
                // Match nodes by regex
                if let Ok(re) = Regex::new(pattern) {
                    for node in nodes {
                        if re.is_match(node.name()) {
                            let name = node.name().to_string();
                            if !result.contains(&name) {
                                result.push(name);
                            }
                        }
                    }
                }
            }
            ProxyMatcher::Special(name) => {
                result.push(name.clone());
            }
            ProxyMatcher::GroupRef(group_name) => {
                // For Clash, keep group references as-is (don't expand)
                // This allows proxy-groups to reference each other
                if !result.contains(group_name) {
                    result.push(group_name.clone());
                }
            }
        }
    }

    result
}

/// Convert parsed groups to Clash format
pub fn to_clash_proxy_groups(
    parsed_groups: &[ParsedProxyGroup],
    nodes: &[Node],
) -> Vec<IndexMap<String, serde_yaml::Value>> {
    // Collect all group names for reference validation
    let all_group_names: Vec<String> = parsed_groups.iter()
        .map(|g| g.name.clone())
        .collect();

    // Convert to Clash format
    let mut result = Vec::new();

    for group in parsed_groups {
        let mut map: IndexMap<String, serde_yaml::Value> = IndexMap::new();
        map.insert("name".into(), serde_yaml::Value::String(group.name.clone()));
        map.insert("type".into(), serde_yaml::Value::String(group.group_type.clone()));

        let proxies = resolve_proxy_group(group, nodes, &all_group_names);
        let proxies_yaml: Vec<serde_yaml::Value> = proxies
            .into_iter()
            .map(serde_yaml::Value::String)
            .collect();
        map.insert("proxies".into(), serde_yaml::Value::Sequence(proxies_yaml));

        // Add URL-test/fallback specific fields
        if group.group_type == "url-test" || group.group_type == "fallback" || group.group_type == "load-balance" {
            if let Some(url) = &group.url {
                map.insert("url".into(), serde_yaml::Value::String(url.clone()));
            } else {
                map.insert("url".into(), serde_yaml::Value::String("http://www.gstatic.com/generate_204".into()));
            }
            map.insert("interval".into(), serde_yaml::Value::Number(
                (group.interval.unwrap_or(300)).into()
            ));
            // Add timeout if specified
            if let Some(timeout) = group.timeout {
                map.insert("timeout".into(), serde_yaml::Value::Number(timeout.into()));
            }
            // Add tolerance (only for url-test)
            if group.group_type == "url-test" {
                if let Some(tolerance) = group.tolerance {
                    map.insert("tolerance".into(), serde_yaml::Value::Number(tolerance.into()));
                }
            }
        }

        result.push(map);
    }

    result
}

/// Convert parsed rules to Clash format
pub fn to_clash_rules(parsed_rules: &[ParsedRule]) -> Vec<String> {
    parsed_rules
        .iter()
        .map(|rule| {
            if rule.rule_type == "MATCH" {
                format!("MATCH,{}", rule.target)
            } else if rule.no_resolve {
                format!("{},{},{},no-resolve", rule.rule_type, rule.value, rule.target)
            } else {
                format!("{},{},{}", rule.rule_type, rule.value, rule.target)
            }
        })
        .collect()
}
