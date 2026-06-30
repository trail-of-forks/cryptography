// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::{
    certificate::Certificate,
    common::Asn1Read,
    crl::{CertificateRevocationList, IssuingDistributionPoint},
    extensions::{
        BasicConstraints, DistributionPoint, DistributionPointName, SequenceOfDistributionPoints,
    },
    name::GeneralName,
    oid::{BASIC_CONSTRAINTS_OID, CRL_DISTRIBUTION_POINTS_OID, ISSUING_DISTRIBUTION_POINT_OID},
};

use crate::{
    ops::CryptoOps, policy::Policy, Chain, ValidationError, ValidationErrorKind, ValidationResult,
};

pub trait RevocationChecker<'a, B: CryptoOps> {
    fn is_revoked(
        &self,
        cert: &Certificate<'_>,
        context: &Chain<'a, B>,
    ) -> ValidationResult<'_, bool, B>;
}

/// https://datatracker.ietf.org/doc/html/rfc5280#section-6.3
pub struct CRLRevocationChecker<'a, B: CryptoOps> {
    crls: &'a [&'a CertificateRevocationList<'a>],
    policy: &'a Policy<'a, B>,
}

/// Verifies that the issuer and the scope of the CRL matches the certificate.
///
/// This maps to step (b) in [RFC 5280 6.3.3].
/// [RFC 5280 6.3.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.3.3
fn crl_applicable_to_cert(
    crl: &CertificateRevocationList<'_>,
    cert: &Certificate<'_>,
) -> Option<()> {
    // Check that the cert's issuer corresponds to the CRL issuer.
    //
    // This only allows for "direct CRL" scenarios. 5280 specifies an "indirect CRL" where the
    // DP's cRLIssuer field contains an issuer separate from the cert's own issuer. We may want to
    // support indirect CRLs in the future, but any implementation would have to account for the
    // fact that the CABF profile explicitly disallows them.
    if cert.tbs_cert.issuer != crl.tbs_cert_list.issuer {
        return None;
    }

    let cert_exts = cert.extensions().ok()?;
    let dps: SequenceOfDistributionPoints<'_, Asn1Read> = cert_exts
        .get_extension(&CRL_DISTRIBUTION_POINTS_OID)?
        .value()
        .ok()?;

    let crl_exts = crl.extensions().ok()?;
    let idp: IssuingDistributionPoint<'_, Asn1Read> = crl_exts
        .get_extension(&ISSUING_DISTRIBUTION_POINT_OID)?
        .value()
        .ok()?;

    // The other match case here is nameRelativeToCRLIssuer, and RFC 5280 has a salient
    // recommendation on the subject:
    //
    // > Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.
    let DistributionPointName::FullName(idp_names) = idp.distribution_point? else {
        return None;
    };
    let idp_uris: Vec<&str> = idp_names
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.0),
            _ => None,
        })
        .collect();

    // Check that a name in one of the cert's DPs matches one of the names in the IDP.
    let mut dp_names_match = false;
    for dp in dps {
        // XX(tnytown): shouldn't be necessary, but rust-analyzer can't infer the type without?
        let _: &DistributionPoint<'_, Asn1Read> = &dp;

        let DistributionPointName::FullName(dp_names) = dp.distribution_point? else {
            return None;
        };

        for name in dp_names {
            let GeneralName::UniformResourceIdentifier(uri) = name else {
                continue;
            };

            if idp_uris.contains(&uri.0) {
                dp_names_match = true;
                break;
            }
        }
    }
    if !dp_names_match {
        return None;
    }

    let cert_bc: BasicConstraints = cert_exts
        .get_extension(&BASIC_CONSTRAINTS_OID)?
        .value()
        .ok()?;

    // If the onlyContainsUserCerts boolean is asserted in the IDP CRL extension, verify that the
    // certificate does not include the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_user_certs && cert_bc.ca {
        return None;
    }

    // If the onlyContainsCACerts boolean is asserted in the IDP CRL extension, verify that the
    // certificate includes the basic constraints extension with the cA boolean asserted.
    if idp.only_contains_ca_certs && !cert_bc.ca {
        return None;
    }

    // Verify that the onlyContainsAttributeCerts boolean is not asserted.
    if idp.only_contains_attribute_certs {
        return None;
    }

    Some(())
}

impl<'a, B: CryptoOps> RevocationChecker<'a, B> for CRLRevocationChecker<'a, B> {
    fn is_revoked(
        &self,
        cert: &Certificate<'_>,
        context: &Chain<'a, B>,
    ) -> ValidationResult<'_, bool, B> {
        // First, find the complete CRL that applies to this certificate, failing with a
        // ValidationError if none are found.
        //
        // We don't support CRL partitioning by reason code, so we shouldn't care about any CRL
        // beyond the first that meets our criteria.
        let crl = self
            .crls
            .iter()
            .find(|crl| {
                if crl_applicable_to_cert(crl, cert).is_none() {
                    return false;
                }

                // We may have temporally partitioned CRLs in CABF parlance, so check the time from within
                // `find()` here and avoid discarding the CRL that covers the correct time.
                if &self.policy.validation_time < crl.tbs_cert_list.this_update.as_datetime() {
                    return false;
                }

                if let Some(ref next_update) = crl.tbs_cert_list.next_update {
                    if &self.policy.validation_time > next_update.as_datetime() {
                        return false;
                    }
                }

                true
            })
            .ok_or(ValidationError::new(
                ValidationErrorKind::RevocationNotDetermined("no applicable CRLs found".into()),
            ))?;

        // Verify that certificate's issuer signed the CRL.
        let issuer = &context[1];
        let pk = match issuer.public_key(&self.policy.ops) {
            Ok(pk) => pk,
            Err(_) => return Ok(false),
        };

        if self.policy.ops.verify_crl_signed_by(crl, pk).is_err() {
            return Ok(false);
        }
        // TODO(tnytown): verify extensions here
        // check issuer keyUsage
        // check CRL extensions, criticality
        // iterate over inner RevokedCertificate entries and do the same
        // maybe this should be done with ExtensionPolicy somehow?

        if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            for revoked in revoked_certs.unwrap_read().clone() {
                if revoked.user_certificate.as_bytes() == cert.tbs_cert.serial.as_bytes() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

impl<'a, B: CryptoOps> CRLRevocationChecker<'a, B> {}
