// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashMap;

use cryptography_x509::{
    certificate::Certificate,
    common::Asn1Read,
    crl::{CertificateRevocationList, IssuingDistributionPoint},
    extensions::{
        BasicConstraints, DistributionPoint, DistributionPointName, SequenceOfDistributionPoints,
    },
    name::{GeneralName, Name},
    oid::{BASIC_CONSTRAINTS_OID, CRL_DISTRIBUTION_POINTS_OID, ISSUING_DISTRIBUTION_POINT_OID},
};

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

pub type RevocationChecker<'a, B> = dyn CheckRevocation<B> + Send + Sync + 'a;

fn crl_distribution_point_matches(
    crl_idp: IssuingDistributionPoint<'_, Asn1Read>,
    cert_dps: SequenceOfDistributionPoints<'_, Asn1Read>,
) -> bool {
    // The other match case here is nameRelativeToCRLIssuer, and RFC 5280 4.2.1.13 has a salient
    // recommendation on the subject:
    //
    // > Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.
    let Some(DistributionPointName::FullName(idp_names)) = crl_idp.distribution_point else {
        return false;
    };

    let idp_uris: Vec<&str> = idp_names
        .filter_map(|ref name| match name {
            // CABF 7.2.2.1: Non-uniformResourceIdentifier GeneralName types MUST NOT be included.
            GeneralName::UniformResourceIdentifier(ref uri) => Some(uri.0),
            _ => None,
        })
        .collect();

    // Check that a name in one of the cert's DPs matches one of the names in the IDP.
    for dp in cert_dps {
        // XX(tnytown): shouldn't be necessary, but rust-analyzer can't infer the type without?
        let _: &DistributionPoint<'_, Asn1Read> = &dp;

        // Same as above: reject anything that isn't a full name.
        let Some(DistributionPointName::FullName(dp_names)) = dp.distribution_point else {
            return false;
        };

        for name in dp_names {
            let GeneralName::UniformResourceIdentifier(uri) = name else {
                continue;
            };

            if idp_uris.contains(&uri.0) {
                return true;
            }
        }
    }

    false
}

/// Verifies that the scope of the CRL matches the certificate.
///
/// This maps to step (b) in [RFC 5280 6.3.3].
/// [RFC 5280 6.3.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.3.3
fn verify_crl_scope(crl: &CertificateRevocationList<'_>, cert: &Certificate<'_>) -> Option<()> {
    // 1) Check that the cert's issuer corresponds to the CRL issuer.
    //
    // This only allows for "direct CRL" scenarios. 5280 specifies an "indirect CRL" where the
    // DP's cRLIssuer field contains an issuer separate from the cert's own issuer. We may want to
    // support indirect CRLs in the future, but any implementation would have to disallow their use
    // in verifying with the CABF profile which prohibits iCRLs.
    if cert.tbs_cert.issuer != crl.tbs_cert_list.issuer {
        return None;
    }

    let cert_exts = cert.extensions().ok()?;
    let cert_bc: BasicConstraints = cert_exts
        .get_extension(&BASIC_CONSTRAINTS_OID)?
        .value()
        .ok()?;

    let crl_exts = crl.extensions().ok()?;
    let idp: IssuingDistributionPoint<'_, Asn1Read> = crl_exts
        .get_extension(&ISSUING_DISTRIBUTION_POINT_OID)?
        .value()
        .ok()?;

    // If onlyContainsUserCerts is asserted in the iDP CRL extension, verify that the certificate
    // does not include the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_user_certs && cert_bc.ca {
        return None;
    }

    // If onlyContainsCACerts is asserted in the iDP CRL extension, verify that the certificate
    // includes the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_ca_certs && !cert_bc.ca {
        return None;
    }

    // Verify that onlyContainsAttributeCerts is not asserted.
    if idp.only_contains_attribute_certs {
        return None;
    }

    let dps: SequenceOfDistributionPoints<'_, Asn1Read> = cert_exts
        .get_extension(&CRL_DISTRIBUTION_POINTS_OID)?
        .value()
        .ok()?;

    // 2) Check DPs (where the cert expects us to find CRLs) against iDP (where the CRL says it's from).
    if !crl_distribution_point_matches(idp, dps) {
        return None;
    }

    Some(())
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
        let _issuer = issuer;
        let _policy = policy;

        // Get the CRL out of our map of verified CRLs keyed by issuer.
        let crl = self
            .by_issuer
            .get(&cert.certificate().tbs_cert.issuer)
            .ok_or(ValidationError::new(
                ValidationErrorKind::RevocationNotDetermined::<B>(
                    "applicable CRL not found for certificate".to_owned(),
                ),
            ))?;

        if verify_crl_scope(crl, cert.certificate()).is_none() {
            return Err(ValidationError::new(
                ValidationErrorKind::RevocationNotDetermined(
                    "CRL is not applicable to certificate".to_owned(),
                ),
            ));
        }

        let revoked_certs =
            &crl.tbs_cert_list
                .revoked_certificates
                .as_ref()
                .ok_or(ValidationError::new(
                    ValidationErrorKind::RevocationNotDetermined::<B>("malformed CRL".to_owned()),
                ))?;

        let is_revoked = revoked_certs.unwrap_read().clone().any(|c| {
            c.user_certificate.as_bytes() == cert.certificate().tbs_cert.serial.as_bytes()
        });

        Ok(is_revoked)
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
