//! Node filtering, renaming, and deduplication using regex patterns

use crate::error::{ConvertError, Result};
use crate::node::Node;
use regex::Regex;
use std::collections::HashSet;

/// Filter nodes based on include/exclude regex patterns
pub fn filter_nodes(
    nodes: Vec<Node>,
    include_pattern: Option<&str>,
    exclude_pattern: Option<&str>,
) -> Result<Vec<Node>> {
    let include_re = match include_pattern {
        Some(p) if !p.is_empty() => {
            Some(Regex::new(p).map_err(|e| ConvertError::InvalidRegex {
                pattern: p.to_string(),
                reason: e.to_string(),
            })?)
        }
        _ => None,
    };

    let exclude_re = match exclude_pattern {
        Some(p) if !p.is_empty() => {
            Some(Regex::new(p).map_err(|e| ConvertError::InvalidRegex {
                pattern: p.to_string(),
                reason: e.to_string(),
            })?)
        }
        _ => None,
    };

    let filtered: Vec<Node> = nodes
        .into_iter()
        .filter(|node| {
            let name = node.name();

            // If include pattern exists, node must match
            if let Some(ref re) = include_re {
                if !re.is_match(name) {
                    return false;
                }
            }

            // If exclude pattern exists, node must NOT match
            if let Some(ref re) = exclude_re {
                if re.is_match(name) {
                    return false;
                }
            }

            true
        })
        .collect();

    Ok(filtered)
}

/// Rename nodes using regex find/replace
pub fn rename_nodes(
    mut nodes: Vec<Node>,
    find_pattern: &str,
    replace_with: &str,
) -> Result<Vec<Node>> {
    if find_pattern.is_empty() {
        return Ok(nodes);
    }

    let re = Regex::new(find_pattern).map_err(|e| ConvertError::InvalidRegex {
        pattern: find_pattern.to_string(),
        reason: e.to_string(),
    })?;

    for node in &mut nodes {
        let name = node.name().to_string();
        let new_name = re.replace_all(&name, replace_with).to_string();
        node.set_name(new_name);
    }

    Ok(nodes)
}

/// Match nodes against a regex pattern (used for proxy group filtering)
pub fn match_nodes_by_pattern<'a>(nodes: &'a [Node], pattern: &str) -> Result<Vec<&'a Node>> {
    let re = Regex::new(pattern).map_err(|e| ConvertError::InvalidRegex {
        pattern: pattern.to_string(),
        reason: e.to_string(),
    })?;

    Ok(nodes.iter().filter(|n| re.is_match(n.name())).collect())
}

/// Deduplicate nodes based on protocol, server, port, and credential.
/// Keeps the first occurrence of each unique node.
pub fn deduplicate_nodes(nodes: Vec<Node>) -> Vec<Node> {
    let mut seen = HashSet::new();
    nodes
        .into_iter()
        .filter(|node| seen.insert(node.dedup_key()))
        .collect()
}

/// Get node names matching a pattern
pub fn get_matching_node_names(nodes: &[Node], pattern: &str) -> Result<Vec<String>> {
    let matched = match_nodes_by_pattern(nodes, pattern)?;
    Ok(matched.iter().map(|n| n.name().to_string()).collect())
}
