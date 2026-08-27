//! Validated, compact proxyIP data prepared away from the `/sub` hot path.

use crate::egress::EgressEntry;
use crate::sha256::sha256;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;

pub const SOURCE_URL: &str = "https://zip.cm.edu.kg/all.json";
pub const ACTIVE_KEY: &str = "proxyip:active:v2";
pub const PREVIOUS_KEY: &str = "proxyip:previous:v2";
pub const FAILURE_KEY: &str = "proxyip:last-failure:v2";
pub const SCHEMA_VERSION: u8 = 2;
pub const MAX_SOURCE_BYTES: usize = 20 * 1024 * 1024;
pub const FETCH_TIMEOUT_SECS: u64 = 30;
pub const STALE_AFTER_MS: u64 = 12 * 60 * 60 * 1_000;

const MIN_ACCEPTED_ENTRIES: usize = 10;
const MAX_PREPARED_ENTRIES: usize = 8_192;
const MAX_PREPARED_PER_COUNTRY: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyIpDataset {
    #[serde(rename = "v")]
    pub schema_version: u8,
    #[serde(rename = "rev")]
    pub revision: String,
    #[serde(rename = "src")]
    pub source: String,
    #[serde(rename = "gen", skip_serializing_if = "Option::is_none")]
    pub source_generated_at: Option<String>,
    #[serde(rename = "at")]
    pub refreshed_at_ms: u64,
    #[serde(rename = "etag", skip_serializing_if = "Option::is_none")]
    pub source_etag: Option<String>,
    #[serde(rename = "ok")]
    pub accepted_count: usize,
    #[serde(rename = "bad")]
    pub rejected_count: usize,
    #[serde(rename = "dup")]
    pub duplicate_count: usize,
    #[serde(rename = "n")]
    pub stored_count: usize,
    /// Country -> `[IPv4 as network-order u32, port]`.
    #[serde(rename = "cc")]
    pub countries: BTreeMap<String, Vec<(u32, u16)>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshFailure {
    pub at_ms: u64,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyIpErrorCode {
    FetchFailed,
    Timeout,
    HttpStatus,
    Oversized,
    DatasetInvalid,
    DatasetUnavailable,
    SuspiciousDrop,
    CacheWriteFailed,
}

impl ProxyIpErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FetchFailed => "ProxyIpFetchFailed",
            Self::Timeout => "ProxyIpFetchTimeout",
            Self::HttpStatus => "ProxyIpFetchHttpStatus",
            Self::Oversized => "ProxyIpDatasetOversized",
            Self::DatasetInvalid => "ProxyIpDatasetInvalid",
            Self::DatasetUnavailable => "ProxyIpDatasetUnavailable",
            Self::SuspiciousDrop => "ProxyIpDatasetSuspiciousDrop",
            Self::CacheWriteFailed => "ProxyIpCacheWriteFailed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyIpError {
    pub code: ProxyIpErrorCode,
    pub detail: String,
}

impl ProxyIpError {
    pub fn new(code: ProxyIpErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn public_message(&self) -> &'static str {
        match self.code {
            ProxyIpErrorCode::DatasetUnavailable => {
                "ProxyIP dataset is not initialized; retry after deployment bootstrap."
            }
            _ => "ProxyIP dataset refresh failed; the previous known-good cache was retained.",
        }
    }
}

impl fmt::Display for ProxyIpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl ProxyIpDataset {
    pub fn from_source(
        bytes: &[u8],
        refreshed_at_ms: u64,
        source_etag: Option<String>,
    ) -> Result<Self, ProxyIpError> {
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
            return Err(ProxyIpError::new(
                if bytes.len() > MAX_SOURCE_BYTES {
                    ProxyIpErrorCode::Oversized
                } else {
                    ProxyIpErrorCode::DatasetInvalid
                },
                format!("source body size is {} bytes", bytes.len()),
            ));
        }

        let document: ApiDocument = serde_json::from_slice(bytes).map_err(|error| {
            ProxyIpError::new(
                ProxyIpErrorCode::DatasetInvalid,
                format!("source JSON is invalid: {error}"),
            )
        })?;
        if document.data.is_empty() {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::DatasetInvalid,
                "source data array is empty",
            ));
        }

        let mut entries = Vec::<EgressEntry>::new();
        let mut positions = HashMap::<(u32, u16), usize>::new();
        let mut rejected_count = 0usize;
        let mut duplicate_count = 0usize;

        for record in document.data {
            let Some(ip_text) = record.ip.as_deref() else {
                rejected_count += 1;
                continue;
            };
            let Ok(ip) = ip_text.parse::<Ipv4Addr>() else {
                rejected_count += 1;
                continue;
            };
            if !is_usable_ipv4(ip) {
                rejected_count += 1;
                continue;
            }

            let mut ports = record.ports;
            if ports.is_empty() {
                if let Some(port) = record.meta.port {
                    ports.push(port);
                }
            }
            ports.sort_unstable();
            ports.dedup();
            ports.retain(|port| is_supported_port(*port));
            if ports.is_empty() {
                rejected_count += 1;
                continue;
            }

            let country = normalize_country(record.meta.country.as_deref());
            let ip_u32 = u32::from(ip);
            for port in ports {
                let key = (ip_u32, port);
                if let Some(index) = positions.get(&key).copied() {
                    duplicate_count += 1;
                    let existing = &mut entries[index].country;
                    if country != *existing && (existing == "XX" || country < *existing) {
                        *existing = country.clone();
                    }
                    continue;
                }
                positions.insert(key, entries.len());
                entries.push(EgressEntry {
                    host: ip.to_string(),
                    port,
                    country: country.clone(),
                });
            }
        }

        if entries.len() < MIN_ACCEPTED_ENTRIES {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::DatasetInvalid,
                format!(
                    "only {} usable host/port entries were accepted",
                    entries.len()
                ),
            ));
        }

        let accepted_count = entries.len();
        let countries = prepare_compact_groups(entries);
        let stored_count = countries.values().map(Vec::len).sum();
        let revision = revision_for(&countries);
        let dataset = Self {
            schema_version: SCHEMA_VERSION,
            revision,
            source: SOURCE_URL.to_string(),
            source_generated_at: document.generated_at,
            refreshed_at_ms,
            source_etag,
            accepted_count,
            rejected_count,
            duplicate_count,
            stored_count,
            countries,
        };
        dataset.validate_for_use()?;
        Ok(dataset)
    }

    pub fn validate_for_use(&self) -> Result<(), ProxyIpError> {
        if self.schema_version != SCHEMA_VERSION
            || self.source != SOURCE_URL
            || self.revision.len() != 24
            || self.refreshed_at_ms == 0
            || self.accepted_count < MIN_ACCEPTED_ENTRIES
            || self.countries.is_empty()
        {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::DatasetInvalid,
                "cached proxyIP metadata failed validation",
            ));
        }

        let mut count = 0usize;
        for (country, entries) in &self.countries {
            if normalize_country(Some(country)) != *country || entries.is_empty() {
                return Err(ProxyIpError::new(
                    ProxyIpErrorCode::DatasetInvalid,
                    "cached proxyIP country group is invalid",
                ));
            }
            for (ip, port) in entries {
                if !is_usable_ipv4(Ipv4Addr::from(*ip)) || !is_supported_port(*port) {
                    return Err(ProxyIpError::new(
                        ProxyIpErrorCode::DatasetInvalid,
                        "cached proxyIP entry is invalid",
                    ));
                }
            }
            count += entries.len();
        }
        if count != self.stored_count || count == 0 || count > MAX_PREPARED_ENTRIES {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::DatasetInvalid,
                "cached proxyIP entry count is inconsistent",
            ));
        }
        Ok(())
    }

    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.refreshed_at_ms) > STALE_AFTER_MS
    }

    pub fn select(
        &self,
        requested_countries: Option<&[String]>,
        preferred_country: Option<&str>,
        max_count: usize,
        rotation_seed: u64,
    ) -> Vec<EgressEntry> {
        if max_count == 0 {
            return Vec::new();
        }

        let groups: Vec<&str> = if let Some(requested) = requested_countries {
            requested
                .iter()
                .filter(|country| self.countries.contains_key(country.as_str()))
                .map(String::as_str)
                .collect()
        } else {
            let mut all: Vec<&str> = self.countries.keys().map(String::as_str).collect();
            if let Some(preferred) = preferred_country {
                if let Some(index) = all.iter().position(|country| *country == preferred) {
                    all.rotate_left(index);
                }
            } else if !all.is_empty() {
                let shift = rotation_seed as usize % all.len();
                all.rotate_left(shift);
            }
            all
        };

        let mut result = Vec::with_capacity(max_count);
        let mut depth = 0usize;
        while result.len() < max_count {
            let mut added = false;
            for (group_index, country) in groups.iter().enumerate() {
                let Some(entries) = self.countries.get(*country) else {
                    continue;
                };
                if entries.is_empty() {
                    continue;
                }
                let offset = rotation_seed
                    .wrapping_add((group_index as u64).wrapping_mul(0x9e37_79b9))
                    as usize
                    % entries.len();
                if depth >= entries.len() {
                    continue;
                }
                let (ip, port) = entries[(offset + depth) % entries.len()];
                result.push(EgressEntry {
                    host: Ipv4Addr::from(ip).to_string(),
                    port,
                    country: (*country).to_string(),
                });
                added = true;
                if result.len() == max_count {
                    break;
                }
            }
            if !added {
                break;
            }
            depth += 1;
        }
        result
    }
}

pub fn validate_promotion(
    previous: Option<&ProxyIpDataset>,
    candidate: &ProxyIpDataset,
) -> Result<(), ProxyIpError> {
    candidate.validate_for_use()?;
    if let Some(previous) = previous {
        previous.validate_for_use()?;
        if previous.accepted_count >= 100
            && candidate.accepted_count.saturating_mul(4) < previous.accepted_count
        {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::SuspiciousDrop,
                format!(
                    "candidate accepted {} entries versus previous {}",
                    candidate.accepted_count, previous.accepted_count
                ),
            ));
        }
    }
    Ok(())
}

pub fn parse_cached(text: &str) -> Result<ProxyIpDataset, ProxyIpError> {
    let dataset: ProxyIpDataset = serde_json::from_str(text).map_err(|error| {
        ProxyIpError::new(
            ProxyIpErrorCode::DatasetInvalid,
            format!("cached dataset JSON is invalid: {error}"),
        )
    })?;
    dataset.validate_for_use()?;
    Ok(dataset)
}

pub fn is_supported_port(port: u16) -> bool {
    matches!(port, 443 | 2053 | 2083 | 2087 | 2096 | 8443)
}

pub fn normalize_country(raw: Option<&str>) -> String {
    let value = raw.unwrap_or("").trim().to_ascii_uppercase();
    match value.as_str() {
        "UK" | "UNITED KINGDOM" => "GB".to_string(),
        "UNITED STATES" | "USA" => "US".to_string(),
        "GERMANY" => "DE".to_string(),
        "JAPAN" => "JP".to_string(),
        "HONG KONG" => "HK".to_string(),
        "SINGAPORE" => "SG".to_string(),
        "NETHERLANDS" => "NL".to_string(),
        "FRANCE" => "FR".to_string(),
        "SOUTH KOREA" => "KR".to_string(),
        "TAIWAN" => "TW".to_string(),
        "AUSTRALIA" => "AU".to_string(),
        "CANADA" => "CA".to_string(),
        "BRAZIL" => "BR".to_string(),
        "INDIA" => "IN".to_string(),
        _ if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()) => value,
        _ => "XX".to_string(),
    }
}

pub fn parse_country_code(raw: &str) -> Result<String, String> {
    let value = raw.trim().to_ascii_uppercase();
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        Ok(if value == "UK" {
            "GB".to_string()
        } else {
            value
        })
    } else {
        Err(format!("invalid ISO country code {raw:?}"))
    }
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn prepare_compact_groups(entries: Vec<EgressEntry>) -> BTreeMap<String, Vec<(u32, u16)>> {
    let mut full = BTreeMap::<String, Vec<(u32, u16)>>::new();
    for entry in entries {
        let Ok(ip) = entry.host.parse::<Ipv4Addr>() else {
            continue;
        };
        full.entry(entry.country)
            .or_default()
            .push((u32::from(ip), entry.port));
    }

    let mut prepared = BTreeMap::<String, Vec<(u32, u16)>>::new();
    let mut total = 0usize;
    let mut depth = 0usize;
    while total < MAX_PREPARED_ENTRIES {
        let mut added = false;
        for (country, values) in &full {
            if depth >= values.len() || depth >= MAX_PREPARED_PER_COUNTRY {
                continue;
            }
            prepared
                .entry(country.clone())
                .or_default()
                .push(values[depth]);
            total += 1;
            added = true;
            if total == MAX_PREPARED_ENTRIES {
                break;
            }
        }
        if !added {
            break;
        }
        depth += 1;
    }
    prepared
}

fn revision_for(countries: &BTreeMap<String, Vec<(u32, u16)>>) -> String {
    let serialized = serde_json::to_vec(countries).expect("compact proxyIP groups serialize");
    let digest = sha256(&serialized);
    let mut output = String::with_capacity(24);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest[..12] {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Deserialize)]
struct ApiDocument {
    #[serde(default)]
    generated_at: Option<String>,
    data: Vec<ApiRecord>,
}

#[derive(Default)]
struct ApiRecord {
    ip: Option<String>,
    ports: Vec<u16>,
    meta: ApiMeta,
}

impl<'de> Deserialize<'de> for ApiRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecordVisitor;

        impl<'de> Visitor<'de> for RecordVisitor {
            type Value = ApiRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a proxyIP record or a value that can be skipped")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut record = ApiRecord::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ip" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            record.ip = value.as_str().map(str::to_string);
                        }
                        "port" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            if let Some(values) = value.as_array() {
                                record.ports = values
                                    .iter()
                                    .filter_map(|value| value.as_u64())
                                    .filter_map(|value| u16::try_from(value).ok())
                                    .collect();
                            }
                        }
                        "meta" => record.meta = map.next_value::<ApiMeta>()?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(record)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(ApiRecord::default())
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(ApiRecord::default())
            }
        }

        deserializer.deserialize_any(RecordVisitor)
    }
}

#[derive(Default)]
struct ApiMeta {
    country: Option<String>,
    port: Option<u16>,
}

impl<'de> Deserialize<'de> for ApiMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MetaVisitor;

        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = ApiMeta;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("proxyIP metadata")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut meta = ApiMeta::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "country" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            meta.country = value.as_str().map(str::to_string);
                        }
                        "_port" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            meta.port = value.as_u64().and_then(|value| u16::try_from(value).ok());
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(meta)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(ApiMeta::default())
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(ApiMeta::default())
            }
        }

        deserializer.deserialize_any(MetaVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(records: &str) -> Vec<u8> {
        format!(r#"{{"generated_at":"2026-08-27T00:00:00Z","data":[{records}]}}"#).into_bytes()
    }

    fn enough_records(extra: &str) -> Vec<u8> {
        let mut records = Vec::new();
        for last in 1..=12 {
            records.push(format!(
                r#"{{"ip":"8.8.8.{last}","port":[443],"meta":{{"country":"us","_port":443}}}}"#
            ));
        }
        records.push(extra.to_string());
        document(&records.join(","))
    }

    #[test]
    fn parses_valid_source_and_normalizes_country_and_ports() {
        let input = enough_records(
            r#"{"ip":"9.9.9.9","port":[8443,443],"meta":{"country":"United States","_port":2053}}"#,
        );
        let dataset = ProxyIpDataset::from_source(&input, 1, Some("etag".into())).unwrap();
        assert_eq!(dataset.accepted_count, 14);
        assert_eq!(dataset.countries["US"].len(), 14);
        assert_eq!(dataset.source_etag.as_deref(), Some("etag"));
    }

    #[test]
    fn skips_partially_malformed_records_without_rejecting_document() {
        let input = enough_records(
            r#"{"ip":42,"port":"bad","meta":null},false,{"ip":"9.9.9.9","port":[443],"meta":{"country":7}}"#,
        );
        let dataset = ProxyIpDataset::from_source(&input, 1, None).unwrap();
        assert_eq!(dataset.accepted_count, 13);
        assert_eq!(dataset.rejected_count, 2);
        assert_eq!(dataset.countries["XX"].len(), 1);
    }

    #[test]
    fn rejects_malformed_empty_and_oversized_documents() {
        assert_eq!(
            ProxyIpDataset::from_source(b"not json", 1, None)
                .unwrap_err()
                .code,
            ProxyIpErrorCode::DatasetInvalid
        );
        assert_eq!(
            ProxyIpDataset::from_source(br#"{"data":[]}"#, 1, None)
                .unwrap_err()
                .code,
            ProxyIpErrorCode::DatasetInvalid
        );
        let oversized = vec![b' '; MAX_SOURCE_BYTES + 1];
        assert_eq!(
            ProxyIpDataset::from_source(&oversized, 1, None)
                .unwrap_err()
                .code,
            ProxyIpErrorCode::Oversized
        );
    }

    #[test]
    fn rejects_private_reserved_and_unsupported_endpoints() {
        let mut records = Vec::new();
        for last in 1..=10 {
            records.push(format!(
                r#"{{"ip":"8.8.4.{last}","port":[443],"meta":{{"country":"US"}}}}"#
            ));
        }
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            records.push(format!(
                r#"{{"ip":"{ip}","port":[443],"meta":{{"country":"US"}}}}"#
            ));
        }
        records.push(r#"{"ip":"9.9.9.9","port":[0,80,65535],"meta":{"country":"US"}}"#.to_string());
        let dataset = ProxyIpDataset::from_source(&document(&records.join(",")), 1, None).unwrap();
        assert_eq!(dataset.accepted_count, 10);
        assert_eq!(dataset.rejected_count, 14);
    }

    #[test]
    fn deduplicates_host_port_with_deterministic_country_resolution() {
        let mut records = Vec::new();
        for last in 1..=10 {
            records.push(format!(
                r#"{{"ip":"8.8.8.{last}","port":[443],"meta":{{"country":"US"}}}}"#
            ));
        }
        records.push(r#"{"ip":"8.8.8.1","port":[443],"meta":{"country":"ZZ"}}"#.to_string());
        records.push(r#"{"ip":"8.8.8.1","port":[443],"meta":{"country":"AA"}}"#.to_string());
        let dataset = ProxyIpDataset::from_source(&document(&records.join(",")), 1, None).unwrap();
        assert_eq!(dataset.accepted_count, 10);
        assert_eq!(dataset.duplicate_count, 2);
        assert!(dataset.countries["AA"]
            .iter()
            .any(|(ip, port)| *ip == u32::from(Ipv4Addr::new(8, 8, 8, 1)) && *port == 443));
    }

    #[test]
    fn suspicious_drop_cannot_replace_known_good_dataset() {
        let previous = ProxyIpDataset {
            schema_version: SCHEMA_VERSION,
            revision: "0123456789abcdef01234567".into(),
            source: SOURCE_URL.into(),
            source_generated_at: None,
            refreshed_at_ms: 1,
            source_etag: None,
            accepted_count: 1_000,
            rejected_count: 0,
            duplicate_count: 0,
            stored_count: 1,
            countries: BTreeMap::from([("US".into(), vec![(0x08080808, 443)])]),
        };
        let mut candidate = previous.clone();
        candidate.accepted_count = 100;
        assert_eq!(
            validate_promotion(Some(&previous), &candidate)
                .unwrap_err()
                .code,
            ProxyIpErrorCode::SuspiciousDrop
        );
    }

    #[test]
    fn country_selection_is_normalized_bounded_and_multi_country() {
        let input = enough_records(r#"{"ip":"9.9.9.9","port":[443],"meta":{"country":"JP"}}"#);
        let dataset = ProxyIpDataset::from_source(&input, 1, None).unwrap();
        let selected = dataset.select(Some(&["JP".into(), "US".into()]), None, 4, 0);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0].country, "JP");
        assert_eq!(selected[1].country, "US");
        assert_eq!(parse_country_code("uk").unwrap(), "GB");
        assert!(parse_country_code("USA").is_err());
    }

    /// Manual schema/resource regression used by release engineering against a
    /// freshly downloaded authoritative response. It is ignored in hermetic CI:
    /// set `VEILWEAVE_ALL_JSON_FIXTURE` and run this test explicitly.
    #[test]
    #[ignore = "requires a freshly downloaded all.json fixture"]
    fn validates_authoritative_live_fixture() {
        let path = std::env::var("VEILWEAVE_ALL_JSON_FIXTURE").unwrap();
        let bytes = std::fs::read(path).unwrap();
        let started = std::time::Instant::now();
        let dataset = ProxyIpDataset::from_source(&bytes, 1, None).unwrap();
        let compact = serde_json::to_vec(&dataset).unwrap();
        assert_eq!(dataset.source, SOURCE_URL);
        assert!(dataset.accepted_count >= MIN_ACCEPTED_ENTRIES);
        assert!(dataset.stored_count > 0);
        assert!(compact.len() < 2 * 1024 * 1024);
        eprintln!(
            "source_bytes={} accepted={} rejected={} stored={} countries={} compact_bytes={} parse_ms={}",
            bytes.len(),
            dataset.accepted_count,
            dataset.rejected_count,
            dataset.stored_count,
            dataset.countries.len(),
            compact.len(),
            started.elapsed().as_millis()
        );
    }
}
