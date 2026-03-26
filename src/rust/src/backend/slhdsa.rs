// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters, SubjectPublicKeyInfo};

const MAX_CONTEXT_BYTES: usize = 255;

pub(crate) fn private_key_from_raw_bytes(
    data: &[u8],
) -> CryptographyResult<SlhDsaShake256fPrivateKey> {
    if data.len() != cryptography_openssl::slhdsa::SHAKE_256F_PRIVATE_KEY_BYTES {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "An SLH-DSA-SHAKE-256f private key is 128 bytes long",
            ),
        ));
    }
    let public_key = cryptography_openssl::slhdsa::public_from_private(data);
    Ok(SlhDsaShake256fPrivateKey {
        private_key: data.to_vec(),
        public_key,
    })
}

pub(crate) fn public_key_from_raw_bytes(
    data: &[u8],
) -> CryptographyResult<SlhDsaShake256fPublicKey> {
    if data.len() != cryptography_openssl::slhdsa::SHAKE_256F_PUBLIC_KEY_BYTES {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "An SLH-DSA-SHAKE-256f public key is 64 bytes long",
            ),
        ));
    }
    Ok(SlhDsaShake256fPublicKey {
        public_key: data.to_vec(),
    })
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.slhdsa")]
pub(crate) struct SlhDsaShake256fPrivateKey {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.slhdsa")]
pub(crate) struct SlhDsaShake256fPublicKey {
    public_key: Vec<u8>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<SlhDsaShake256fPrivateKey> {
    let (public_key, private_key) = cryptography_openssl::slhdsa::generate_key();
    Ok(SlhDsaShake256fPrivateKey {
        private_key,
        public_key,
    })
}

#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<SlhDsaShake256fPrivateKey> {
    Ok(private_key_from_raw_bytes(data.as_bytes())?)
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<SlhDsaShake256fPublicKey> {
    Ok(public_key_from_raw_bytes(data)?)
}

#[pyo3::pymethods]
impl SlhDsaShake256fPrivateKey {
    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("context must be at most 255 bytes long"),
            ));
        }
        let sig =
            cryptography_openssl::slhdsa::sign(&self.private_key, data.as_bytes(), ctx_bytes)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> SlhDsaShake256fPublicKey {
        SlhDsaShake256fPublicKey {
            public_key: self.public_key.clone(),
        }
    }

    fn private_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.private_key)
    }

    fn private_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let password = match crate::backend::utils::validate_private_key_encryption(
            py,
            encoding,
            format,
            encryption_algorithm,
            true,
        )? {
            crate::backend::utils::PrivateKeyPassword::Raw => {
                return Ok(pyo3::types::PyBytes::new(py, &self.private_key));
            }
            crate::backend::utils::PrivateKeyPassword::Password(p) => p,
        };

        if format != crate::serialization::PrivateFormat::PKCS8 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "SLH-DSA private keys only support Raw or PKCS8 format",
                ),
            ));
        }

        let private_key_der = asn1::write_single(&self.private_key.as_slice()).map_err(|e| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(e.to_string()))
        })?;
        let pki = cryptography_key_parsing::pkcs8::PrivateKeyInfo {
            version: 0,
            algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::SlhDsaShake256f,
            },
            private_key: &private_key_der,
            attributes: None,
        };
        let pkcs8_der = asn1::write_single(&pki).map_err(|e| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(e.to_string()))
        })?;

        crate::backend::utils::encode_pkcs8_der(py, pkcs8_der, &password, encoding)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl SlhDsaShake256fPublicKey {
    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("context must be at most 255 bytes long"),
            ));
        }
        let valid = cryptography_openssl::slhdsa::verify(
            signature.as_bytes(),
            &self.public_key,
            data.as_bytes(),
            ctx_bytes,
        )
        .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn public_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.public_key)
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if encoding == crate::serialization::Encoding::Raw
            || format == crate::serialization::PublicFormat::Raw
        {
            if encoding != crate::serialization::Encoding::Raw
                || format != crate::serialization::PublicFormat::Raw
            {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "When using Raw both encoding and format must be Raw",
                    ),
                ));
            }
            return Ok(pyo3::types::PyBytes::new(py, &self.public_key));
        }

        if format != crate::serialization::PublicFormat::SubjectPublicKeyInfo {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "SLH-DSA public keys only support Raw or SubjectPublicKeyInfo format",
                ),
            ));
        }

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::SlhDsaShake256f,
            },
            subject_public_key: asn1::BitString::new(&self.public_key, 0).unwrap(),
        };
        let der_bytes = asn1::write_single(&spki).map_err(|e| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(e.to_string()))
        })?;

        crate::asn1::encode_der_data(py, "PUBLIC KEY".to_string(), der_bytes, encoding)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.public_key == other.public_key
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod slhdsa {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, SlhDsaShake256fPrivateKey,
        SlhDsaShake256fPublicKey,
    };
}
