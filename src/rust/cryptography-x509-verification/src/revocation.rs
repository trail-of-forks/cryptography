// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509::crl::CertificateRevocationList;
use cryptography_x509::extensions::KeyUsage;
use cryptography_x509::oid::KEY_USAGE_OID;

use crate::ops::{CryptoOps, VerificationCertificate};
use crate::policy::Policy;
use crate::{ValidationError, ValidationErrorKind, ValidationResult};

/// Trait for checking certificate revocation during path validation.
pub trait RevocationChecker<B: CryptoOps> {
    /// Check whether `cert` has been revoked.
    ///
    /// `issuer` is the candidate issuing CA (already validated).
    /// `policy` provides access to validation_time and crypto ops.
    ///
    /// Returns `Ok(true)` if the certificate is revoked.
    /// Returns `Ok(false)` if the certificate is not revoked.
    /// Returns `Err(ValidationError)` if the revocation status cannot be determined.
    fn is_revoked<'chain>(
        &self,
        cert: &Certificate<'_>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B>;
}

/// A revocation checker that validates certificates against a set of CRLs.
pub struct CRLRevocationChecker<'a> {
    crls: &'a [&'a CertificateRevocationList<'a>],
}

impl<'a> CRLRevocationChecker<'a> {
    pub fn new(crls: &'a [&'a CertificateRevocationList<'a>]) -> Self {
        Self { crls }
    }
}

impl<B: CryptoOps> RevocationChecker<B> for CRLRevocationChecker<'_> {
    fn is_revoked<'chain>(
        &self,
        cert: &Certificate<'_>,
        issuer: &VerificationCertificate<'chain, B>,
        policy: &Policy<'_, B>,
    ) -> ValidationResult<'chain, bool, B> {
        let mut found_valid_crl = false;

        for crl in self.crls {
            // Step 1: Find applicable CRLs by matching issuer name.
            if crl.tbs_cert_list.issuer != cert.tbs_cert.issuer {
                continue;
            }

            // Step 2a: Verify CRL signature against the issuer's public key.
            let pk = match issuer.public_key(&policy.ops) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            if policy.ops.verify_crl_signature(crl, pk).is_err() {
                continue;
            }

            // Step 2b: Check the issuer's KeyUsage extension for cRLSign.
            let issuer_extensions = match issuer.certificate().extensions() {
                Ok(exts) => exts,
                Err(_) => continue,
            };
            if let Some(ku_ext) = issuer_extensions.get_extension(&KEY_USAGE_OID) {
                match ku_ext.value::<KeyUsage<'_>>() {
                    Ok(ku) => {
                        if !ku.crl_sign() {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }

            // Step 2c: Check CRL algorithm consistency.
            if crl.tbs_cert_list.signature != crl.signature_algorithm {
                continue;
            }

            // Step 2d: Check temporal validity.
            if &policy.validation_time < crl.tbs_cert_list.this_update.as_datetime() {
                continue;
            }
            if let Some(ref next_update) = crl.tbs_cert_list.next_update {
                if &policy.validation_time > next_update.as_datetime() {
                    continue;
                }
            }

            // This CRL passed all validation checks.
            found_valid_crl = true;

            // Step 2e: Search for the certificate's serial in the revoked list.
            if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
                for revoked in revoked_certs.unwrap_read().clone() {
                    if revoked.user_certificate.as_bytes() == cert.tbs_cert.serial.as_bytes() {
                        return Ok(true);
                    }
                }
            }
        }

        // Fail closed: if no valid CRL was found, we cannot determine
        // revocation status.
        if !found_valid_crl {
            return Err(ValidationError::new(ValidationErrorKind::Other(
                "no valid CRL found for certificate".to_string(),
            )));
        }

        // Certificate is not revoked.
        Ok(false)
    }
}
