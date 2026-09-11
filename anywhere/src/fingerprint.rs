use std::sync::Arc;

use boring::ssl::SslContextBuilder;
use boring::ssl::SslRef;
use foreign_types_shared::ForeignTypeRef;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::TlsCertificatePaths;

use crate::outbound::common::apply_fingerprint_to_ctx;

// ---------------------------------------------------------------------------
// FingerprintHook – Chrome TLS fingerprint mimicry
// ---------------------------------------------------------------------------

/// [`ConnectionHook`] that implements Chrome TLS fingerprint mimicry.
///
/// Configures cipher suites, signature algorithms, certificate compression,
/// ALPS, and (optionally) ECH to match Chrome's TLS ClientHello as closely as
/// possible.
pub struct FingerprintHook {
    /// Optional base64-encoded ECH config list for the server.
    pub ech_config: Option<Vec<u8>>,
    /// Offer a GREASE ECH extension when no real config is available, so
    /// "carries an ECH extension" is not a client distinguisher.
    pub ech_grease: bool,
}

impl FingerprintHook {
    /// Creates a new [`FingerprintHook`], optionally decoding a base64 ECH
    /// config.
    pub fn new(ech_config_b64: Option<String>, ech_grease: bool) -> Self {
        let ech_config = ech_config_b64.and_then(|s| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .inspect_err(|e| log::warn!("Failed to decode ECH config: {e:?}"))
                .ok()
        });

        Self { ech_config, ech_grease }
    }

    /// Boxes this hook into an optional [`Arc`] suitable for
    /// [`Hooks`](tokio_quiche::settings::Hooks).
    pub fn into_arc_option(
        fp: bool, ech_config: Option<String>, ech: bool,
    ) -> Option<Arc<dyn ConnectionHook + Send + Sync + 'static>> {
        if fp || ech {
            Some(Arc::new(Self::new(ech_config, ech)))
        } else {
            None
        }
    }
}

impl ConnectionHook for FingerprintHook {
    fn create_custom_ssl_context_builder(
        &self, _settings: Option<TlsCertificatePaths<'_>>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .expect("failed to create SslContextBuilder");
        apply_fingerprint_to_ctx(&mut builder);
        Some(builder)
    }

    fn configure_ssl(&self, ssl: &mut SslRef) {
        // ALPS (Application-Layer Protocol Settings) for HTTP/3.
        // Chrome sends this extension in the ClientHello.
        let alpn_h3 = b"h3";
        let settings: &[u8] = &[];
        unsafe {
            boring_sys::SSL_add_application_settings(
                ssl.as_ptr() as *mut boring_sys::SSL,
                alpn_h3.as_ptr(),
                alpn_h3.len(),
                settings.as_ptr(),
                settings.len(),
            );
        }

        // ECH (Encrypted Client Hello).
        if self.ech_grease && self.ech_config.is_none() {
            // No published config: send a grease offer so "carries ECH" is
            // not a client distinguisher (Chrome does the same).
            ssl.set_enable_ech_grease(true);
        }
        if let Some(ref ech) = self.ech_config {
            if let Err(e) = ssl.set_ech_config_list(ech) {
                log::warn!("Failed to set ECH config list: {e:?}");
            }
        }
    }
}
