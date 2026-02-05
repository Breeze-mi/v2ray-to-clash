//! HTTP client for fetching subscriptions and remote configs

use std::time::Duration;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{ConvertError, Result};

/// Subscription info parsed from `subscription-userinfo` header
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionInfo {
    /// Upload traffic in bytes
    pub upload: Option<u64>,
    /// Download traffic in bytes
    pub download: Option<u64>,
    /// Total traffic allowance in bytes
    pub total: Option<u64>,
    /// Expiry timestamp (Unix epoch seconds)
    pub expire: Option<i64>,
}

impl SubscriptionInfo {
    /// Parse the subscription-userinfo header value.
    /// Format: `upload=bytes; download=bytes; total=bytes; expire=timestamp`
    fn parse(header_value: &str) -> Self {
        let mut info = Self::default();
        for part in header_value.split(';') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "upload" => info.upload = value.parse().ok(),
                    "download" => info.download = value.parse().ok(),
                    "total" => info.total = value.parse().ok(),
                    "expire" => info.expire = value.parse().ok(),
                    _ => {}
                }
            }
        }
        info
    }
}

/// Result of fetching a URL with subscription info
pub struct FetchWithInfoResult {
    pub body: String,
    pub subscription_info: Option<SubscriptionInfo>,
}

/// HTTP client with configured timeout
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("clash-verge/v2.0.0")
            .build()
            .map_err(|e| ConvertError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client })
    }

    /// Fetch content from a URL
    pub async fn fetch(&self, url: &str) -> Result<String> {
        let result = self.fetch_with_info(url).await?;
        Ok(result.body)
    }

    /// Fetch content from a URL, also returning subscription-userinfo if present
    pub async fn fetch_with_info(&self, url: &str) -> Result<FetchWithInfoResult> {
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ConvertError::Timeout(url.to_string())
                } else {
                    ConvertError::FetchError {
                        url: url.to_string(),
                        reason: e.to_string(),
                    }
                }
            })?;

        if !response.status().is_success() {
            return Err(ConvertError::FetchError {
                url: url.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        // Extract subscription-userinfo header before consuming the response
        let subscription_info = response.headers()
            .get("subscription-userinfo")
            .and_then(|v| v.to_str().ok())
            .map(SubscriptionInfo::parse);

        let body = response.text().await.map_err(|e| ConvertError::FetchError {
            url: url.to_string(),
            reason: e.to_string(),
        })?;

        Ok(FetchWithInfoResult {
            body,
            subscription_info,
        })
    }

    /// Fetch multiple URLs concurrently
    pub async fn fetch_all(&self, urls: &[&str]) -> Vec<Result<String>> {
        let futures: Vec<_> = urls.iter().map(|url| self.fetch(url)).collect();
        futures::future::join_all(futures).await
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new(30).expect("Failed to create default HTTP client")
    }
}
