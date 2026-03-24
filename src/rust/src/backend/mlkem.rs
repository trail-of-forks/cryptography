// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::types;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mlkem")]
pub(crate) struct MlKem768PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    seed: [u8; 64],
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mlkem")]
pub(crate) struct MlKem768PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn private_key_from_seed(seed: [u8; 64]) -> CryptographyResult<MlKem768PrivateKey> {
    let pkey = cryptography_openssl::mlkem::new_from_seed(&seed)?;
    Ok(MlKem768PrivateKey { pkey, seed })
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlKem768PublicKey {
    MlKem768PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<MlKem768PrivateKey> {
    let mut seed = [0u8; 64];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    private_key_from_seed(seed)
}

#[pyo3::pyfunction]
fn from_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768PrivateKey> {
    let seed: [u8; 64] = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 seed is 64 bytes long")
    })?;
    private_key_from_seed(seed).map_err(|e| e.into())
}

// NO-COVERAGE-START
#[pyo3::pymethods]
// NO-COVERAGE-END
impl MlKem768PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let shared_secret =
            cryptography_openssl::mlkem::decapsulate(&self.pkey, ciphertext.as_bytes()).map_err(
                |_| pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-768 ciphertext"),
            )?;
        Ok(pyo3::types::PyBytes::new(py, &shared_secret))
    }

    fn public_key(&self) -> CryptographyResult<MlKem768PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlKem768PublicKey {
            pkey: cryptography_openssl::mlkem::new_raw_public_key(&raw_bytes)?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new(py, &self.seed))
    }

    fn private_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !encryption_algorithm.is_instance(&types::KEY_SERIALIZATION_ENCRYPTION.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Encryption algorithm must be a KeySerializationEncryption instance",
                ),
            ));
        }

        if encoding == crate::serialization::Encoding::Raw
            || format == crate::serialization::PrivateFormat::Raw
        {
            if encoding != crate::serialization::Encoding::Raw
                || format != crate::serialization::PrivateFormat::Raw
                || !encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)?
            {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                ).into());
            }
            return Ok(pyo3::types::PyBytes::new(py, &self.seed));
        }

        if format != crate::serialization::PrivateFormat::PKCS8 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "ML-KEM-768 private keys only support PKCS8 and Raw formats",
            )
            .into());
        }

        let py_password;
        let password = if encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)? {
            b"" as &[u8]
        } else if encryption_algorithm.is_instance(&types::BEST_AVAILABLE_ENCRYPTION.get(py)?)?
            || (encryption_algorithm.is_instance(&types::ENCRYPTION_BUILDER.get(py)?)?
                && encryption_algorithm
                    .getattr(pyo3::intern!(py, "_format"))?
                    .extract::<crate::serialization::PrivateFormat>()?
                    == format)
        {
            py_password = encryption_algorithm
                .getattr(pyo3::intern!(py, "password"))?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            &py_password
        } else {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Unsupported encryption type"),
            ));
        };

        if password.len() > 1023 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Passwords longer than 1023 bytes are not supported by this backend",
                ),
            ));
        }

        let parsed = cryptography_key_parsing::ParsedPrivateKey::MlKem768(self.seed);
        let (tag, der_bytes) = if password.is_empty() {
            (
                "PRIVATE KEY",
                cryptography_key_parsing::pkcs8::serialize_private_key(&parsed)?,
            )
        } else {
            (
                "ENCRYPTED PRIVATE KEY",
                cryptography_key_parsing::pkcs8::serialize_encrypted_private_key(
                    &parsed, password,
                )?,
            )
        };

        crate::asn1::encode_der_data(py, tag.to_string(), der_bytes, encoding)
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

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<MlKem768PublicKey> {
    let pkey = cryptography_openssl::mlkem::new_raw_public_key(data).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 public key is 1184 bytes long")
    })?;
    Ok(MlKem768PublicKey { pkey })
}

// NO-COVERAGE-START
#[pyo3::pymethods]
// NO-COVERAGE-END
impl MlKem768PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ciphertext, shared_secret) = cryptography_openssl::mlkem::encapsulate(&self.pkey)?;
        let ss = pyo3::types::PyBytes::new(py, &shared_secret);
        let ct = pyo3::types::PyBytes::new(py, &ciphertext);
        Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
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
pub(crate) mod mlkem {
    #[pymodule_export]
    use super::{
        from_public_bytes, from_seed_bytes, generate_key, MlKem768PrivateKey, MlKem768PublicKey,
    };
}
