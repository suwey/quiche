//! XPadding middleware: inject padding into HTTP requests and validate
//! padding in HTTP responses.
//!
//! This is the Transport-layer integration of `obfuscation/padding.rs`.
//! Per the architecture design (§6.3), XPadding operates as a Transport
//! built-in middleware rather than through the `ObfuscationLayer` trait,
//! because it needs to manipulate HTTP headers/URLs directly.

use crate::obfuscation::padding::{XPaddingConfig, XPaddingPlacement};

// ---------------------------------------------------------------------------
// XPaddingMiddleware
// ---------------------------------------------------------------------------

/// Middleware that injects XPadding into HTTP requests and validates
/// padding in HTTP responses.
#[derive(Debug, Clone)]
pub struct XPaddingMiddleware {
    config: XPaddingConfig,
}

impl XPaddingMiddleware {
    pub fn new(config: XPaddingConfig) -> Self {
        Self { config }
    }

    /// Generate a padding value using the config's method and random length.
    pub fn generate_padding(&self) -> String {
        self.config.generate()
    }

    /// Apply padding to an HTTP request being built.
    ///
    /// Modifies `url` (for query placement) and `headers` (for header/cookie/
    /// referer placement) in place.
    ///
    /// ## Default mode (`obfs_mode = false`)
    ///
    /// Padding is placed in the `Referer` header as a URL query parameter
    /// with key `x_padding`. This matches Xray's default behavior.
    ///
    /// ## Custom mode (`obfs_mode = true`)
    ///
    /// Padding placement is configured via `placement`, `key`, and `header`.
    /// Apply padding to an HTTP request being built.
    ///
    /// Modifies `url` (for query placement) and `headers` (for header/cookie/
    /// referer placement) in place.
    ///
    /// ## Default mode (`obfs_mode = false`)
    ///
    /// Padding is placed in the `Referer` header as a URL query parameter
    /// with key `x_padding`. This matches Xray's default behavior.
    ///
    /// ## Custom mode (`obfs_mode = true`)
    ///
    /// Padding placement is configured via `placement`, `key`, and `header`.
    pub fn apply_to_request_mut(
        &self, url: &mut String, headers: &mut Vec<(String, String)>,
    ) {
        let padding = self.generate_padding();
        if padding.is_empty() {
            return;
        }

        if !self.config.obfs_mode {
            // Default: Referer URL query
            let referer = if url.contains('?') {
                format!("{}&x_padding={}", url, padding)
            } else {
                format!("{}?x_padding={}", url, padding)
            };
            headers.push(("Referer".to_string(), referer));
        } else {
            // Custom placement
            match self.config.placement {
                XPaddingPlacement::Header => {
                    headers.push((self.config.header.clone(), padding));
                },
                XPaddingPlacement::Cookie => {
                    headers.push((
                        "Cookie".to_string(),
                        format!("{}={}", self.config.key, padding),
                    ));
                },
                XPaddingPlacement::Query => {
                    // ✅ Append padding directly to URL query string
                    let sep = if url.contains('?') { '&' } else { '?' };
                    url.push_str(&format!(
                        "{}{}={}",
                        sep, self.config.key, padding
                    ));
                },
                XPaddingPlacement::QueryInHeader => {
                    let header_value =
                        format!("{}?{}={}", url, self.config.key, padding);
                    headers.push((self.config.header.clone(), header_value));
                },
            }
        }
    }

    /// Legacy wrapper: applies padding using an immutable `&str` URL.
    ///
    /// Query placement is not effective in this mode (falls back to header).
    /// Prefer [`apply_to_request_mut`] when the URL can be mutated.
    pub fn apply_to_request(
        &self, url: &str, headers: &mut Vec<(String, String)>,
    ) {
        let mut url_owned = url.to_string();
        self.apply_to_request_mut(&mut url_owned, headers);
    }

    /// Validate the X-Padding response header.
    ///
    /// Returns `true` if the padding is valid or absent (padding is optional
    /// in responses). Returns `false` only if a padding header is present
    /// but fails validation.
    pub fn validate_response(&self, headers: &http::HeaderMap) -> bool {
        // Look for X-Padding response header
        if let Some(padding_value) = headers.get("X-Padding") {
            if let Ok(s) = padding_value.to_str() {
                return self.config.is_valid(s);
            }
            return false; // Invalid header value
        }
        // No X-Padding header - valid (padding is optional in responses)
        true
    }

    /// Generate a response padding header for server-side use (M5).
    // M5: server-side
    ///
    /// Returns `(header_name, value)` or `None` if padding is disabled.
    pub fn generate_response_padding(&self) -> Option<(String, String)> {
        let padding = self.generate_padding();
        if padding.is_empty() {
            None
        } else {
            Some(("X-Padding".to_string(), padding))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscation::padding::{
        PaddingMethod, XPaddingConfig, XPaddingPlacement,
    };
    use crate::obfuscation::range::Range;

    #[test]
    fn default_mode_referer_header() {
        let mw = XPaddingMiddleware::new(XPaddingConfig::default());
        let mut headers = Vec::new();
        mw.apply_to_request("/xhttp/session123", &mut headers);

        // Should add a Referer header
        let referer = headers.iter().find(|(k, _)| k == "Referer");
        assert!(referer.is_some(), "Referer header should be present");
        let value = &referer.unwrap().1;
        assert!(
            value.contains("x_padding="),
            "Referer should contain x_padding: got {value}"
        );
        assert!(
            value.contains("/xhttp/session123"),
            "Referer should contain the URL: got {value}"
        );
    }

    #[test]
    fn custom_header_placement() {
        let cfg = XPaddingConfig {
            obfs_mode: true,
            placement: XPaddingPlacement::Header,
            header: "X-Padding".to_string(),
            ..Default::default()
        };
        let mw = XPaddingMiddleware::new(cfg);
        let mut headers = Vec::new();
        mw.apply_to_request("/xhttp", &mut headers);

        let padding = headers.iter().find(|(k, _)| k == "X-Padding");
        assert!(padding.is_some(), "X-Padding header should be present");
        assert!(
            !padding.unwrap().1.is_empty(),
            "Padding value should not be empty"
        );
    }

    #[test]
    fn custom_cookie_placement() {
        let cfg = XPaddingConfig {
            obfs_mode: true,
            placement: XPaddingPlacement::Cookie,
            key: "pad".to_string(),
            ..Default::default()
        };
        let mw = XPaddingMiddleware::new(cfg);
        let mut headers = Vec::new();
        mw.apply_to_request("/xhttp", &mut headers);

        let cookie = headers.iter().find(|(k, _)| k == "Cookie");
        assert!(cookie.is_some(), "Cookie header should be present");
        assert!(
            cookie.unwrap().1.starts_with("pad="),
            "Cookie should start with 'pad=': got {}",
            cookie.unwrap().1
        );
    }

    #[test]
    fn custom_query_in_header_placement() {
        let cfg = XPaddingConfig {
            obfs_mode: true,
            placement: XPaddingPlacement::QueryInHeader,
            header: "X-Custom".to_string(),
            key: "pad".to_string(),
            ..Default::default()
        };
        let mw = XPaddingMiddleware::new(cfg);
        let mut headers = Vec::new();
        mw.apply_to_request("/xhttp", &mut headers);

        let custom = headers.iter().find(|(k, _)| k == "X-Custom");
        assert!(custom.is_some());
        assert!(custom.unwrap().1.contains("?pad="));
    }

    #[test]
    fn validate_response_valid_padding() {
        let cfg = XPaddingConfig::default(); // repeat-x, 100-1000
        let mw = XPaddingMiddleware::new(cfg);
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Padding", "X".repeat(200).parse().unwrap());
        assert!(mw.validate_response(&headers));
    }

    #[test]
    fn validate_response_invalid_padding() {
        let cfg = XPaddingConfig::default(); // repeat-x, 100-1000
        let mw = XPaddingMiddleware::new(cfg);
        let mut headers = http::HeaderMap::new();
        // Too short (< 100)
        headers.insert("X-Padding", "X".repeat(10).parse().unwrap());
        assert!(!mw.validate_response(&headers));
    }

    #[test]
    fn validate_response_no_padding_header() {
        let mw = XPaddingMiddleware::new(XPaddingConfig::default());
        let headers = http::HeaderMap::new();
        // No X-Padding header - should be valid (optional)
        assert!(mw.validate_response(&headers));
    }

    #[test]
    fn validate_response_tokenish() {
        let cfg = XPaddingConfig {
            method: PaddingMethod::Tokenish,
            ..Default::default()
        };
        let mw = XPaddingMiddleware::new(cfg);
        // Generate a valid tokenish padding and put it in the response
        let padding = mw.generate_padding();
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Padding", padding.parse().unwrap());
        assert!(mw.validate_response(&headers));
    }

    #[test]
    fn generate_response_padding() {
        let mw = XPaddingMiddleware::new(XPaddingConfig {
            bytes: Range::new(100, 100),
            ..Default::default()
        });
        let result = mw.generate_response_padding();
        assert!(result.is_some());
        let (name, value) = result.unwrap();
        assert_eq!(name, "X-Padding");
        assert_eq!(value.len(), 100);
        assert!(value.chars().all(|c| c == 'X'));
    }
}
