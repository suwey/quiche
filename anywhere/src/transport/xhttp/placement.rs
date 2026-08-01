//! Session metadata placement: inject session_id / seq into HTTP requests.
//!
//! Mirrors Xray's `splithttp` placement logic. Metadata can go in:
//! - URL path (`/path/session_id`)
//! - URL query (`?session=xxx&seq=0`)
//! - HTTP header (`session: xxx`)
//! - Cookie (`Cookie: session=xxx`)

use super::config::SessionPlacement;

// ---------------------------------------------------------------------------
// PlacementConfig
// ---------------------------------------------------------------------------

/// Configuration for where to place session_id and seq in HTTP requests.
#[derive(Debug, Clone)]
pub struct PlacementConfig {
    pub session_id_placement: SessionPlacement,
    pub session_id_key: String,
    pub seq_placement: SessionPlacement,
    pub seq_key: String,
}

impl PlacementConfig {
    /// Build the request URL and collect extra headers for the given
    /// session_id and optional seq.
    ///
    /// Returns `(url, extra_headers)` where `extra_headers` is a list of
    /// `(name, value)` pairs to add to the HTTP request.
    pub fn build_request_meta(
        &self,
        base_path: &str,
        session_id: &str,
        seq: Option<u64>,
    ) -> (String, Vec<(String, String)>) {
        let mut path = base_path.trim_end_matches('/').to_string();
        let mut query_parts: Vec<String> = Vec::new();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut cookie_parts: Vec<String> = Vec::new();

        // session_id placement
        match self.session_id_placement {
            SessionPlacement::Path => {
                path.push('/');
                path.push_str(session_id);
            }
            SessionPlacement::Query => {
                query_parts.push(format!("{}={}", self.session_id_key, session_id));
            }
            SessionPlacement::Header => {
                headers.push((self.session_id_key.clone(), session_id.to_string()));
            }
            SessionPlacement::Cookie => {
                cookie_parts.push(format!("{}={}", self.session_id_key, session_id));
            }
        }

        // seq placement (only for packet-up / stream-up, not stream-one)
        if let Some(seq) = seq {
            match self.seq_placement {
                SessionPlacement::Path => {
                    path.push('/');
                    path.push_str(&seq.to_string());
                }
                SessionPlacement::Query => {
                    query_parts.push(format!("{}={}", self.seq_key, seq));
                }
                SessionPlacement::Header => {
                    headers.push((self.seq_key.clone(), seq.to_string()));
                }
                SessionPlacement::Cookie => {
                    cookie_parts.push(format!("{}={}", self.seq_key, seq));
                }
            }
        }

        // Merge cookie parts into a single Cookie header
        if !cookie_parts.is_empty() {
            headers.push(("Cookie".to_string(), cookie_parts.join("; ")));
        }

        // Build final URL
        let url = if query_parts.is_empty() {
            path
        } else {
            format!("{}?{}", path, query_parts.join("&"))
        };

        (url, headers)
    }
}

/// Extract session_id from an HTTP request (server-side, for M5).
///
/// Looks in path, query, header, or cookie depending on `placement`.
pub fn extract_session_id(
    path: &str,
    query: &str,
    headers: &http::HeaderMap,
    placement: SessionPlacement,
    key: &str,
) -> Option<String> {
    match placement {
        SessionPlacement::Path => {
            // session_id is the last path segment
            path.trim_end_matches('/').rsplit('/').next().map(|s| s.to_string())
        }
        SessionPlacement::Query => {
            extract_query_value(query, key)
        }
        SessionPlacement::Header => {
            headers.get(key).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
        }
        SessionPlacement::Cookie => {
            headers.get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|c| extract_cookie_value(c, key))
        }
    }
}

fn extract_query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some(key) {
            return parts.next().map(|s| s.to_string());
        }
    }
    None
}

fn extract_cookie_value(cookie_header: &str, key: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{}=", key)) {
            return Some(rest.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PlacementConfig {
        PlacementConfig {
            session_id_placement: SessionPlacement::Path,
            session_id_key: "session".to_string(),
            seq_placement: SessionPlacement::Query,
            seq_key: "seq".to_string(),
        }
    }

    #[test]
    fn session_id_in_path() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Path,
            ..default_config()
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", None);
        assert_eq!(url, "/xhttp/abc123");
        assert!(headers.is_empty());
    }

    #[test]
    fn session_id_in_query() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Query,
            session_id_key: "session".to_string(),
            ..default_config()
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", None);
        assert_eq!(url, "/xhttp?session=abc123");
        assert!(headers.is_empty());
    }

    #[test]
    fn session_id_in_header() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Header,
            session_id_key: "X-Session".to_string(),
            ..default_config()
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", None);
        assert_eq!(url, "/xhttp");
        assert_eq!(headers, vec![("X-Session".to_string(), "abc123".to_string())]);
    }

    #[test]
    fn session_id_in_cookie() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Cookie,
            session_id_key: "session".to_string(),
            ..default_config()
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", None);
        assert_eq!(url, "/xhttp");
        assert_eq!(headers, vec![("Cookie".to_string(), "session=abc123".to_string())]);
    }

    #[test]
    fn session_id_and_seq_different_placements() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Path,
            session_id_key: "session".to_string(),
            seq_placement: SessionPlacement::Query,
            seq_key: "seq".to_string(),
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", Some(42));
        assert_eq!(url, "/xhttp/abc123?seq=42");
        assert!(headers.is_empty());
    }

    #[test]
    fn session_id_and_seq_both_in_cookie() {
        let cfg = PlacementConfig {
            session_id_placement: SessionPlacement::Cookie,
            session_id_key: "session".to_string(),
            seq_placement: SessionPlacement::Cookie,
            seq_key: "seq".to_string(),
        };
        let (url, headers) = cfg.build_request_meta("/xhttp", "abc123", Some(42));
        assert_eq!(url, "/xhttp");
        assert_eq!(headers, vec![("Cookie".to_string(), "session=abc123; seq=42".to_string())]);
    }

    #[test]
    fn path_with_trailing_slash() {
        let cfg = default_config();
        let (url, _) = cfg.build_request_meta("/xhttp/", "abc123", None);
        assert_eq!(url, "/xhttp/abc123");
    }

    #[test]
    fn root_path() {
        let cfg = default_config();
        let (url, _) = cfg.build_request_meta("/", "abc123", None);
        assert_eq!(url, "/abc123");
    }

    #[test]
    fn extract_session_id_from_path() {
        let headers = http::HeaderMap::new();
        let id = extract_session_id("/xhttp/abc123", "", &headers, SessionPlacement::Path, "session");
        assert_eq!(id, Some("abc123".to_string()));
    }

    #[test]
    fn extract_session_id_from_query() {
        let headers = http::HeaderMap::new();
        let id = extract_session_id("/xhttp", "session=abc123", &headers, SessionPlacement::Query, "session");
        assert_eq!(id, Some("abc123".to_string()));
    }

    #[test]
    fn extract_session_id_from_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert("session", "abc123".parse().unwrap());
        let id = extract_session_id("/xhttp", "", &headers, SessionPlacement::Header, "session");
        assert_eq!(id, Some("abc123".to_string()));
    }

    #[test]
    fn extract_session_id_from_cookie() {
        let mut headers = http::HeaderMap::new();
        headers.insert("cookie", "session=abc123; other=xyz".parse().unwrap());
        let id = extract_session_id("/xhttp", "", &headers, SessionPlacement::Cookie, "session");
        assert_eq!(id, Some("abc123".to_string()));
    }
}
