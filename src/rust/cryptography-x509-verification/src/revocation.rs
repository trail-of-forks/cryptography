// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashMap;

use cryptography_x509::{certificate::Certificate, crl::CertificateRevocationList, name::Name};

use crate::{
    ops::{CryptoOps, VerificationCertificate},
    policy::Policy,
    ValidationError, ValidationErrorKind, ValidationResult,
};

pub trait CheckRevocation<B: CryptoOps> {
    fn is_revoked<'chain>(
        &self,
        cert: &VerificationCertificate<'chain, B>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B>;
}

pub struct CrlRevocationChecker<'a> {
    by_issuer: HashMap<Name<'a>, &'a CertificateRevocationList<'a>>,
}

impl<'a, B: CryptoOps> CheckRevocation<B> for CrlRevocationChecker<'a> {
    fn is_revoked<'chain>(
        &self,
        cert: &VerificationCertificate<'chain, B>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B> {
        let _crls = &self.by_issuer;
        let _cert = cert;
        let _issuer = issuer;
        let _policy = policy;

        Err(ValidationError::new(ValidationErrorKind::FatalError(
            "unimplemented",
        )))
    }
}

impl<'a> CrlRevocationChecker<'a> {
    /// Constructs a new revocation checker.
    pub fn new<B: CryptoOps>(
        _ops: B,
        _crls: impl IntoIterator<Item = (&'a Certificate<'a>, &'a CertificateRevocationList<'a>)>,
    ) -> Self {
        Self {
            by_issuer: HashMap::new(),
        }
    }
}

pub type RevocationChecker<'a, B> = dyn CheckRevocation<B> + Send + Sync + 'a;
