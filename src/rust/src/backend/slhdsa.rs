// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const MAX_CONTEXT_BYTES: usize = 255;

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.primitives.asymmetric.slhdsa"
)]
// NO-COVERAGE-END
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SlhDsaParameterSet {
    #[pyo3(name = "SHAKE_256F")]
    Shake256f,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.slhdsa")]
pub(crate) struct SlhDsa256PrivateKey {
    parameter_set: SlhDsaParameterSet,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.slhdsa")]
pub(crate) struct SlhDsa256PublicKey {
    parameter_set: SlhDsaParameterSet,
    public_key: Vec<u8>,
}

#[pyo3::pyfunction]
fn generate_key(parameter_set: SlhDsaParameterSet) -> SlhDsa256PrivateKey {
    let (public_key, private_key) = cryptography_openssl::slhdsa::generate_key();
    SlhDsa256PrivateKey {
        parameter_set,
        private_key,
        public_key,
    }
}

#[pyo3::pyfunction]
fn from_private_bytes(
    parameter_set: SlhDsaParameterSet,
    data: CffiBuf<'_>,
) -> pyo3::PyResult<SlhDsa256PrivateKey> {
    let data = data.as_bytes();
    if data.len() != cryptography_openssl::slhdsa::SHAKE_256F_PRIVATE_KEY_BYTES {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "An SLH-DSA-256 private key is 128 bytes long",
        ));
    }
    let public_key = cryptography_openssl::slhdsa::public_from_private(data);
    Ok(SlhDsa256PrivateKey {
        parameter_set,
        private_key: data.to_vec(),
        public_key,
    })
}

#[pyo3::pyfunction]
fn from_public_bytes(
    parameter_set: SlhDsaParameterSet,
    data: &[u8],
) -> pyo3::PyResult<SlhDsa256PublicKey> {
    if data.len() != cryptography_openssl::slhdsa::SHAKE_256F_PUBLIC_KEY_BYTES {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "An SLH-DSA-256 public key is 64 bytes long",
        ));
    }
    Ok(SlhDsa256PublicKey {
        parameter_set,
        public_key: data.to_vec(),
    })
}

// NO-COVERAGE-START
#[pyo3::pymethods]
// NO-COVERAGE-END
impl SlhDsa256PrivateKey {
    #[getter]
    fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

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

    fn public_key(&self) -> SlhDsa256PublicKey {
        SlhDsa256PublicKey {
            parameter_set: self.parameter_set,
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
        if !encryption_algorithm.is_instance(&crate::types::NO_ENCRYPTION.get(py)?)? {
            if encryption_algorithm
                .is_instance(&crate::types::KEY_SERIALIZATION_ENCRYPTION.get(py)?)?
            {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "SLH-DSA keys do not support PKCS#8/PEM serialization yet",
                    ),
                ));
            }
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "encryption_algorithm must be an instance of NoEncryption",
                ),
            ));
        }

        match (encoding, format) {
            (crate::serialization::Encoding::Raw, crate::serialization::PrivateFormat::Raw) => {
                Ok(pyo3::types::PyBytes::new(py, &self.private_key))
            }
            _ => Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "SLH-DSA private keys only support Raw encoding with Raw format",
                ),
            )),
        }
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

// NO-COVERAGE-START
#[pyo3::pymethods]
// NO-COVERAGE-END
impl SlhDsa256PublicKey {
    #[getter]
    fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

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
        cryptography_openssl::slhdsa::verify(
            signature.as_bytes(),
            &self.public_key,
            data.as_bytes(),
            ctx_bytes,
        )
        .map_err(|_| CryptographyError::from(exceptions::InvalidSignature::new_err(())))
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
        match (encoding, format) {
            (crate::serialization::Encoding::Raw, crate::serialization::PublicFormat::Raw) => {
                Ok(pyo3::types::PyBytes::new(py, &self.public_key))
            }
            _ => Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "SLH-DSA public keys only support Raw encoding with Raw format",
                ),
            )),
        }
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.parameter_set == other.parameter_set && self.public_key == other.public_key
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
        from_private_bytes, from_public_bytes, generate_key, SlhDsa256PrivateKey,
        SlhDsa256PublicKey, SlhDsaParameterSet,
    };
}
