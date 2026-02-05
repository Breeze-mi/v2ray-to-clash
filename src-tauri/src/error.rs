//! Error types for the subscription converter

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConvertError {
    #[error("Failed to fetch URL: {url} - {reason}")]
    FetchError { url: String, reason: String },

    #[error("Failed to decode base64 content: {0}")]
    Base64DecodeError(String),

    #[error("Failed to parse URL: {0}")]
    UrlParseError(String),

    #[error("Failed to parse INI config: {0}")]
    IniParseError(String),

    #[error("Failed to serialize YAML: {0}")]
    YamlSerializeError(String),

    #[error("Invalid node format: {protocol} - {reason}")]
    InvalidNodeFormat { protocol: String, reason: String },

    #[error("Invalid regex pattern: {pattern} - {reason}")]
    InvalidRegex { pattern: String, reason: String },

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Missing required field: {field} in {context}")]
    MissingField { field: String, context: String },

    #[error("Request timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl serde::Serialize for ConvertError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ConvertError>;
