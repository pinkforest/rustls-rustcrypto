#![deny(
    clippy::all,
    // TODO: clippy::pedantic,
    clippy::alloc_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core
)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::sync::Arc;

use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(feature = "getrandom")]
use rand_core::OsRng as ChosenRng;

#[cfg(feature = "tls12")]
use rustls::SignatureScheme;

use rand_core::CryptoRng;
use rand_core::RngCore;

// TODO: Ditto.
use std::sync::Mutex;
use std::ops::DerefMut;

pub struct Provider<'rng, R: RngCore + CryptoRng + Send + Sync + 'rng> {
    pub(crate) csprng: Arc<Mutex<&'rng mut R>>,
}

impl<'rng, R: RngCore + CryptoRng + Send + Sync> core::fmt::Debug for Provider<'rng, R> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}



impl<'rng, R: RngCore + CryptoRng + Send + Sync> Provider<'rng, R> {

    /// ```
    /// let rustcrypto_provider = rustls_rustcrypto::Provider::new();
    /// ```
    #[cfg(feature = "getrandom")]
    pub fn new() -> Provider<'rng, R> {
        Self::new_from_rng(ChosenRng)
    }

    /// ```
    /// let mut rng = rand_core::OsRng;
    /// let rustcrypto_provider = rustls_rustcrypto::Provider::new_from_rng(&mut rng);
    /// ```
    pub fn new_from_rng(csprng: &'rng mut R) -> Provider<R> {        
        Provider { csprng: Arc::new(Mutex::new(csprng)) }
    }
    pub fn rustls_crypto_provider(&'static self) -> CryptoProvider {

        let mut csprng_m = self.csprng.lock().unwrap();
        let mut csprng = csprng_m.deref_mut();
        
        CryptoProvider {
            cipher_suites: ALL_CIPHER_SUITES.to_vec(),
            //kx_groups: kx::ALL_KX_GROUPS.to_vec(),
            kx_groups: kx::generate_kx_groups(&mut csprng),
            signature_verification_algorithms: verify::ALGORITHMS,
            secure_random: self,
            key_provider: self,
        }
    }
}


impl<'rng, R: RngCore + CryptoRng + Send + Sync> SecureRandom for Provider<'rng, R> {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        let x = self.csprng.lock().unwrap()
            .try_fill_bytes(bytes)
            .map_err(|_| GetRandomFailed);
        x
    }
}

impl<'rng, R: RngCore + CryptoRng + Send + Sync> KeyProvider for Provider<'rng, R> {
    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::any_supported_type(&key_der)
    }
}

#[cfg(feature = "tls12")]
const TLS12_ECDSA_SCHEMES: [SignatureScheme; 4] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
];

#[cfg(feature = "tls12")]
const TLS12_RSA_SCHEMES: [SignatureScheme; 6] = [
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::gcm::Tls12Aes128Gcm,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA384),
        aead_alg: &aead::gcm::Tls12Aes256Gcm,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::chacha20::Chacha20Poly1305,
    });

#[cfg(feature = "tls12")]
const TLS_ECDHE_ECDSA_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_RSA_SCHEMES,
        aead_alg: &aead::gcm::Tls12Aes128Gcm,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_RSA_SCHEMES,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA384),
        aead_alg: &aead::gcm::Tls12Aes256Gcm,
    });

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &TLS12_RSA_SCHEMES,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
        aead_alg: &aead::chacha20::Chacha20Poly1305,
    });

#[cfg(feature = "tls12")]
const TLS_ECDHE_RSA_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

#[cfg(feature = "tls12")]
const TLS12_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    TLS_ECDHE_ECDSA_SUITES,
    TLS_ECDHE_RSA_SUITES
);

#[cfg(not(feature = "tls12"))]
const TLS12_SUITES: &[SupportedCipherSuite] = &[];

pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::gcm::Tls13Aes128Gcm,
        quic: None,
    });

pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA384),
        aead_alg: &aead::gcm::Tls13Aes256Gcm,
        quic: None,
    });

const TLS13_AES_SUITES: &[SupportedCipherSuite] =
    &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];

pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::chacha20::Chacha20Poly1305,
        quic: None,
    });

const TLS13_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    TLS13_AES_SUITES,
    &[TLS13_CHACHA20_POLY1305_SHA256]
);

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    if cfg!(feature = "tls12") {
        TLS12_SUITES
    } else {
        &[]
    },
    TLS13_SUITES,
);

mod aead;
mod hash;
mod hmac;
mod kx;
mod misc;
pub mod quic;
pub mod sign;
mod verify;
