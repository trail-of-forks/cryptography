#![allow(
    clippy::useless_attribute,
    clippy::redundant_static_lifetimes,
    dead_code,
    clippy::missing_safety_doc,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::unnecessary_wraps,
    clippy::needless_question_mark,
    unused_unsafe,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unnecessary_fallible_conversions,
    unused_imports,
    non_snake_case,
    non_local_definitions,
    clippy::declare_interior_mutable_const,
    clippy::undocumented_unsafe_blocks,
    clippy::blocks_in_conditions,
    clippy::module_inception
)]

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use pyo3::types::PyAnyMethods;
const MAX_CONTEXT_BYTES: usize = 255;
pub(crate) struct MlDsa65PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}
impl ::pyo3::types::DerefToPyAny for MlDsa65PrivateKey {}
unsafe impl ::pyo3::type_object::PyTypeInfo for MlDsa65PrivateKey {
    const NAME: &str = <Self as ::pyo3::PyClass>::NAME;
    const MODULE: ::std::option::Option<&str> =
        <Self as ::pyo3::impl_::pyclass::PyClassImpl>::MODULE;
    #[inline]
    fn type_object_raw(py: ::pyo3::Python<'_>) -> *mut ::pyo3::ffi::PyTypeObject {
        use ::pyo3::prelude::PyTypeMethods;
        <MlDsa65PrivateKey as ::pyo3::impl_::pyclass::PyClassImpl>::lazy_type_object()
            .get_or_try_init(py)
            .unwrap_or_else(|e| {
                ::pyo3::impl_::pyclass::type_object_init_failed(
                    py,
                    e,
                    <Self as ::pyo3::PyClass>::NAME,
                )
            })
            .as_type_ptr()
    }
}
impl ::pyo3::PyClass for MlDsa65PrivateKey {
    const NAME: &str = "MlDsa65PrivateKey";
    type Frozen = ::pyo3::pyclass::boolean_struct::True;
}
impl<'py> ::pyo3::conversion::IntoPyObject<'py> for MlDsa65PrivateKey {
    type Target = Self;
    type Output = ::pyo3::Bound<'py, <Self as ::pyo3::conversion::IntoPyObject<'py>>::Target>;
    type Error = ::pyo3::PyErr;
    fn into_pyobject(
        self,
        py: ::pyo3::Python<'py>,
    ) -> ::std::result::Result<
        <Self as ::pyo3::conversion::IntoPyObject<'py>>::Output,
        <Self as ::pyo3::conversion::IntoPyObject<'py>>::Error,
    > {
        ::pyo3::Bound::new(py, self)
    }
}
const _: () = {
    #[allow(unused_import)]
    use ::pyo3::impl_::pyclass::Probe as _;
    ::pyo3::impl_::deprecated::HasAutomaticFromPyObject::<
        { ::pyo3::impl_::pyclass::IsClone::<MlDsa65PrivateKey>::VALUE },
    >::MSG
};
impl ::pyo3::impl_::pyclass::ExtractPyClassWithClone for MlDsa65PrivateKey {}
const _: () = ::pyo3::impl_::pyclass::assert_pyclass_send_sync::<MlDsa65PrivateKey>();
impl ::pyo3::impl_::pyclass::PyClassImpl for MlDsa65PrivateKey {
    const MODULE: ::std::option::Option<&str> =
        ::core::option::Option::Some("cryptography.hazmat.bindings._rust.openssl.mldsa");
    const IS_BASETYPE: bool = false;
    const IS_SUBCLASS: bool = false;
    const IS_MAPPING: bool = false;
    const IS_SEQUENCE: bool = false;
    const IS_IMMUTABLE_TYPE: bool = false;
    type Layout = <Self::BaseNativeType as ::pyo3::impl_::pyclass::PyClassBaseType>::Layout<Self>;
    type BaseType = ::pyo3::PyAny;
    type ThreadChecker = ::pyo3::impl_::pyclass::NoopThreadChecker;
    type PyClassMutability = <<::pyo3::PyAny as ::pyo3::impl_::pyclass::PyClassBaseType>::PyClassMutability as ::pyo3::impl_::pycell::PyClassMutability>::ImmutableChild;
    type Dict = ::pyo3::impl_::pyclass::PyClassDummySlot;
    type WeakRef = ::pyo3::impl_::pyclass::PyClassDummySlot;
    type BaseNativeType = ::pyo3::PyAny;
    fn items_iter() -> ::pyo3::impl_::pyclass::PyClassItemsIter {
        use ::pyo3::impl_::pyclass::*;
        let collector = PyClassImplCollector::<Self>::new();
        static INTRINSIC_ITEMS: PyClassItems = PyClassItems {
            methods: &[],
            slots: &[],
        };
        PyClassItemsIter::new(&INTRINSIC_ITEMS, collector.py_methods())
    }
    const RAW_DOC: &'static ::std::ffi::CStr = c"";
    const DOC: &'static ::std::ffi::CStr = {
        use ::pyo3::impl_;
        use impl_::pyclass::Probe as _;
        const DOC_PIECES: &'static [&'static [u8]] = impl_::pyclass::doc::PyClassDocGenerator::<
            MlDsa65PrivateKey,
            { impl_::pyclass::HasNewTextSignature::<MlDsa65PrivateKey>::VALUE },
        >::DOC_PIECES;
        const LEN: usize = impl_::concat::combined_len(DOC_PIECES);
        const DOC: &'static [u8] = &impl_::concat::combine_to_array::<LEN>(DOC_PIECES);
        impl_::pyclass::doc::doc_bytes_as_cstr(DOC)
    };
    fn lazy_type_object() -> &'static ::pyo3::impl_::pyclass::LazyTypeObject<Self> {
        use ::pyo3::impl_::pyclass::LazyTypeObject;
        static TYPE_OBJECT: LazyTypeObject<MlDsa65PrivateKey> = LazyTypeObject::new();
        &TYPE_OBJECT
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PrivateKey {}
impl MlDsa65PrivateKey {
    #[doc(hidden)]
    pub const _PYO3_DEF: ::pyo3::impl_::pymodule::AddClassToModule<Self> =
        ::pyo3::impl_::pymodule::AddClassToModule::new();
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PrivateKey {}
pub(crate) struct MlDsa65PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}
impl ::pyo3::types::DerefToPyAny for MlDsa65PublicKey {}
unsafe impl ::pyo3::type_object::PyTypeInfo for MlDsa65PublicKey {
    const NAME: &str = <Self as ::pyo3::PyClass>::NAME;
    const MODULE: ::std::option::Option<&str> =
        <Self as ::pyo3::impl_::pyclass::PyClassImpl>::MODULE;
    #[inline]
    fn type_object_raw(py: ::pyo3::Python<'_>) -> *mut ::pyo3::ffi::PyTypeObject {
        use ::pyo3::prelude::PyTypeMethods;
        <MlDsa65PublicKey as ::pyo3::impl_::pyclass::PyClassImpl>::lazy_type_object()
            .get_or_try_init(py)
            .unwrap_or_else(|e| {
                ::pyo3::impl_::pyclass::type_object_init_failed(
                    py,
                    e,
                    <Self as ::pyo3::PyClass>::NAME,
                )
            })
            .as_type_ptr()
    }
}
impl ::pyo3::PyClass for MlDsa65PublicKey {
    const NAME: &str = "MlDsa65PublicKey";
    type Frozen = ::pyo3::pyclass::boolean_struct::True;
}
impl<'py> ::pyo3::conversion::IntoPyObject<'py> for MlDsa65PublicKey {
    type Target = Self;
    type Output = ::pyo3::Bound<'py, <Self as ::pyo3::conversion::IntoPyObject<'py>>::Target>;
    type Error = ::pyo3::PyErr;
    fn into_pyobject(
        self,
        py: ::pyo3::Python<'py>,
    ) -> ::std::result::Result<
        <Self as ::pyo3::conversion::IntoPyObject<'py>>::Output,
        <Self as ::pyo3::conversion::IntoPyObject<'py>>::Error,
    > {
        ::pyo3::Bound::new(py, self)
    }
}
const _: () = {
    #[allow(unused_import)]
    use ::pyo3::impl_::pyclass::Probe as _;
    ::pyo3::impl_::deprecated::HasAutomaticFromPyObject::<
        { ::pyo3::impl_::pyclass::IsClone::<MlDsa65PublicKey>::VALUE },
    >::MSG
};
impl ::pyo3::impl_::pyclass::ExtractPyClassWithClone for MlDsa65PublicKey {}
const _: () = ::pyo3::impl_::pyclass::assert_pyclass_send_sync::<MlDsa65PublicKey>();
impl ::pyo3::impl_::pyclass::PyClassImpl for MlDsa65PublicKey {
    const MODULE: ::std::option::Option<&str> =
        ::core::option::Option::Some("cryptography.hazmat.bindings._rust.openssl.mldsa");
    const IS_BASETYPE: bool = false;
    const IS_SUBCLASS: bool = false;
    const IS_MAPPING: bool = false;
    const IS_SEQUENCE: bool = false;
    const IS_IMMUTABLE_TYPE: bool = false;
    type Layout = <Self::BaseNativeType as ::pyo3::impl_::pyclass::PyClassBaseType>::Layout<Self>;
    type BaseType = ::pyo3::PyAny;
    type ThreadChecker = ::pyo3::impl_::pyclass::NoopThreadChecker;
    type PyClassMutability = <<::pyo3::PyAny as ::pyo3::impl_::pyclass::PyClassBaseType>::PyClassMutability as ::pyo3::impl_::pycell::PyClassMutability>::ImmutableChild;
    type Dict = ::pyo3::impl_::pyclass::PyClassDummySlot;
    type WeakRef = ::pyo3::impl_::pyclass::PyClassDummySlot;
    type BaseNativeType = ::pyo3::PyAny;
    fn items_iter() -> ::pyo3::impl_::pyclass::PyClassItemsIter {
        use ::pyo3::impl_::pyclass::*;
        let collector = PyClassImplCollector::<Self>::new();
        static INTRINSIC_ITEMS: PyClassItems = PyClassItems {
            methods: &[],
            slots: &[],
        };
        PyClassItemsIter::new(&INTRINSIC_ITEMS, collector.py_methods())
    }
    const RAW_DOC: &'static ::std::ffi::CStr = c"";
    const DOC: &'static ::std::ffi::CStr = {
        use ::pyo3::impl_;
        use impl_::pyclass::Probe as _;
        const DOC_PIECES: &'static [&'static [u8]] = impl_::pyclass::doc::PyClassDocGenerator::<
            MlDsa65PublicKey,
            { impl_::pyclass::HasNewTextSignature::<MlDsa65PublicKey>::VALUE },
        >::DOC_PIECES;
        const LEN: usize = impl_::concat::combined_len(DOC_PIECES);
        const DOC: &'static [u8] = &impl_::concat::combine_to_array::<LEN>(DOC_PIECES);
        impl_::pyclass::doc::doc_bytes_as_cstr(DOC)
    };
    fn lazy_type_object() -> &'static ::pyo3::impl_::pyclass::LazyTypeObject<Self> {
        use ::pyo3::impl_::pyclass::LazyTypeObject;
        static TYPE_OBJECT: LazyTypeObject<MlDsa65PublicKey> = LazyTypeObject::new();
        &TYPE_OBJECT
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PublicKey {}
impl MlDsa65PublicKey {
    #[doc(hidden)]
    pub const _PYO3_DEF: ::pyo3::impl_::pymodule::AddClassToModule<Self> =
        ::pyo3::impl_::pymodule::AddClassToModule::new();
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PublicKey {}
pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa65PrivateKey {
    MlDsa65PrivateKey {
        pkey: pkey.to_owned(),
    }
}
pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa65PublicKey {
    MlDsa65PublicKey {
        pkey: pkey.to_owned(),
    }
}
fn generate_key() -> CryptographyResult<MlDsa65PrivateKey> {
    let mut seed = [0u8; cryptography_openssl::mldsa::MLDSA65_SEED_BYTES];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(&seed)?;
    Ok(MlDsa65PrivateKey { pkey })
}
#[doc(hidden)]
mod generate_key {
    pub(crate) struct MakeDef;
    pub static _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef = MakeDef::_PYO3_DEF;
}
#[allow(unknown_lints, non_local_definitions)]
impl generate_key::MakeDef {
    #[allow(clippy::declare_interior_mutable_const)]
    const _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef =
        ::pyo3::impl_::pyfunction::PyFunctionDef::from_method_def(
            ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                c"generate_key",
                {
                    struct Def;
                    impl
                        ::pyo3::impl_::trampoline::MethodDef<
                            ::pyo3::impl_::trampoline::noargs::Func,
                        > for Def
                    {
                        const METH: ::pyo3::impl_::trampoline::noargs::Func =
                            __pyfunction_generate_key;
                    }
                    ::pyo3::impl_::trampoline::noargs::<Def>
                },
                c"generate_key()\n--\n\n",
            )
            .flags(::pyo3::ffi::METH_STATIC),
        );
}
#[allow(non_snake_case)]
unsafe fn __pyfunction_generate_key<'py>(
    py: ::pyo3::Python<'py>,
    _slf: *mut ::pyo3::ffi::PyObject,
) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
    let function = generate_key;
    let result = {
        #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
        let ret = function();
        {
            let result = {
                let obj = ret;
                #[allow(
                    clippy::useless_conversion,
                    reason = "needed for Into<PyErr> conversion, may be redundant"
                )]
                ::pyo3::impl_::wrap::converter(&obj)
                    .wrap(obj)
                    .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
            };
            ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
        }
    };
    result
}
fn from_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PrivateKey> {
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(data.as_bytes()).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 seed is 32 bytes long")
    })?;
    Ok(MlDsa65PrivateKey { pkey })
}
#[doc(hidden)]
mod from_seed_bytes {
    pub(crate) struct MakeDef;
    pub static _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef = MakeDef::_PYO3_DEF;
}
#[allow(unknown_lints, non_local_definitions)]
impl from_seed_bytes::MakeDef {
    #[allow(clippy::declare_interior_mutable_const)]
    const _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef =
        ::pyo3::impl_::pyfunction::PyFunctionDef::from_method_def(
            ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                c"from_seed_bytes",
                {
                    struct Def;
                    impl
                        ::pyo3::impl_::trampoline::MethodDef<
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                        > for Def
                    {
                        const METH:
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func =
                            __pyfunction_from_seed_bytes;
                    }
                    ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                },
                c"from_seed_bytes(data)\n--\n\n",
            )
            .flags(::pyo3::ffi::METH_STATIC),
        );
}
#[allow(non_snake_case)]
unsafe fn __pyfunction_from_seed_bytes<'py>(
    py: ::pyo3::Python<'py>,
    _slf: *mut ::pyo3::ffi::PyObject,
    _args: *const *mut ::pyo3::ffi::PyObject,
    _nargs: ::pyo3::ffi::Py_ssize_t,
    _kwnames: *mut ::pyo3::ffi::PyObject,
) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
    let function = from_seed_bytes;
    const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
        ::pyo3::impl_::extract_argument::FunctionDescription {
            cls_name: ::std::option::Option::None,
            func_name: "from_seed_bytes",
            positional_parameter_names: &["data"],
            positional_only_parameters: 0usize,
            required_positional_parameters: 1usize,
            keyword_only_parameters: &[],
        };
    let mut output = [::std::option::Option::None; 1usize];
    let (_args, _kwargs) = DESCRIPTION
        .extract_arguments_fastcall::<
            ::pyo3::impl_::extract_argument::NoVarargs,
            ::pyo3::impl_::extract_argument::NoVarkeywords,
        >(py, _args, _nargs, _kwnames, &mut output)?;
    let result = {
        #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
        let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
        let ret = function({
            #[allow(unused_imports, reason = "`Probe` trait used on negative case only")]
            use ::pyo3::impl_::pyclass::Probe as _;
            ::pyo3::impl_::extract_argument::extract_argument(
                unsafe {
                    ::pyo3::impl_::extract_argument::unwrap_required_argument(output[0usize])
                },
                &mut holder_0,
                "data",
            )?
        });
        {
            let result = {
                let obj = ret;
                #[allow(
                    clippy::useless_conversion,
                    reason = "needed for Into<PyErr> conversion, may be redundant"
                )]
                ::pyo3::impl_::wrap::converter(&obj)
                    .wrap(obj)
                    .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
            };
            ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
        }
    };
    result
}
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<MlDsa65PublicKey> {
    let pkey = cryptography_openssl::mldsa::new_raw_public_key(data).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 public key is 1952 bytes long")
    })?;
    Ok(MlDsa65PublicKey { pkey })
}
#[doc(hidden)]
mod from_public_bytes {
    pub(crate) struct MakeDef;
    pub static _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef = MakeDef::_PYO3_DEF;
}
#[allow(unknown_lints, non_local_definitions)]
impl from_public_bytes::MakeDef {
    #[allow(clippy::declare_interior_mutable_const)]
    const _PYO3_DEF: ::pyo3::impl_::pyfunction::PyFunctionDef =
        ::pyo3::impl_::pyfunction::PyFunctionDef::from_method_def(
            ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                c"from_public_bytes",
                {
                    struct Def;
                    impl
                        ::pyo3::impl_::trampoline::MethodDef<
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                        > for Def
                    {
                        const METH:
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func =
                            __pyfunction_from_public_bytes;
                    }
                    ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                },
                c"from_public_bytes(data)\n--\n\n",
            )
            .flags(::pyo3::ffi::METH_STATIC),
        );
}
#[allow(non_snake_case)]
unsafe fn __pyfunction_from_public_bytes<'py>(
    py: ::pyo3::Python<'py>,
    _slf: *mut ::pyo3::ffi::PyObject,
    _args: *const *mut ::pyo3::ffi::PyObject,
    _nargs: ::pyo3::ffi::Py_ssize_t,
    _kwnames: *mut ::pyo3::ffi::PyObject,
) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
    let function = from_public_bytes;
    const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
        ::pyo3::impl_::extract_argument::FunctionDescription {
            cls_name: ::std::option::Option::None,
            func_name: "from_public_bytes",
            positional_parameter_names: &["data"],
            positional_only_parameters: 0usize,
            required_positional_parameters: 1usize,
            keyword_only_parameters: &[],
        };
    let mut output = [::std::option::Option::None; 1usize];
    let (_args, _kwargs) = DESCRIPTION
        .extract_arguments_fastcall::<
            ::pyo3::impl_::extract_argument::NoVarargs,
            ::pyo3::impl_::extract_argument::NoVarkeywords,
        >(py, _args, _nargs, _kwnames, &mut output)?;
    let result = {
        #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
        let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
        let ret = function({
            #[allow(unused_imports, reason = "`Probe` trait used on negative case only")]
            use ::pyo3::impl_::pyclass::Probe as _;
            ::pyo3::impl_::extract_argument::extract_argument(
                unsafe {
                    ::pyo3::impl_::extract_argument::unwrap_required_argument(output[0usize])
                },
                &mut holder_0,
                "data",
            )?
        });
        {
            let result = {
                let obj = ret;
                #[allow(
                    clippy::useless_conversion,
                    reason = "needed for Into<PyErr> conversion, may be redundant"
                )]
                ::pyo3::impl_::wrap::converter(&obj)
                    .wrap(obj)
                    .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
            };
            ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
        }
    };
    result
}
impl MlDsa65PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let sig = cryptography_openssl::mldsa::sign(&self.pkey, data.as_bytes(), ctx_bytes)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }
    fn public_key(&self) -> CryptographyResult<MlDsa65PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa65PublicKey {
            pkey: cryptography_openssl::mldsa::new_raw_public_key(&raw_bytes)?,
        })
    }
    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let pkcs8_der = self.pkey.private_key_to_pkcs8()?;
        let pki =
            asn1::parse_single::<cryptography_key_parsing::pkcs8::PrivateKeyInfo<'_>>(&pkcs8_der)
                .unwrap();
        let cryptography_key_parsing::pkcs8::MlDsaPrivateKey::Seed(seed) =
            asn1::parse_single::<cryptography_key_parsing::pkcs8::MlDsaPrivateKey<'_>>(
                pki.private_key,
            )
            .unwrap();
        Ok(pyo3::types::PyBytes::new(py, seed))
    }
    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if encoding == crate::serialization::Encoding::Raw
            && format == crate::serialization::PrivateFormat::Raw
            && encryption_algorithm.is_instance(&crate::types::NO_ENCRYPTION.get(py)?)?
        {
            return slf.borrow().private_bytes_raw(py);
        }
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
        )
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
#[allow(unknown_lints, non_local_definitions)]
impl ::pyo3::impl_::pyclass::PyMethods<MlDsa65PrivateKey>
    for ::pyo3::impl_::pyclass::PyClassImplCollector<MlDsa65PrivateKey>
{
    fn py_methods(self) -> &'static ::pyo3::impl_::pyclass::PyClassItems {
        static ITEMS: ::pyo3::impl_::pyclass::PyClassItems = ::pyo3::impl_::pyclass::PyClassItems {
            methods: &[
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"sign",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PrivateKey::__pymethod_sign__;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"sign($self, data, context=None)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                        c"public_key",
                        {
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::noargs::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::noargs::Func =
                                    MlDsa65PrivateKey::__pymethod_public_key__;
                            }
                            ::pyo3::impl_::trampoline::noargs::<Def>
                        },
                        c"public_key($self)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                        c"private_bytes_raw",
                        {
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::noargs::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::noargs::Func =
                                    MlDsa65PrivateKey::__pymethod_private_bytes_raw__;
                            }
                            ::pyo3::impl_::trampoline::noargs::<Def>
                        },
                        c"private_bytes_raw($self)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"private_bytes",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PrivateKey::__pymethod_private_bytes__;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"private_bytes($self, encoding, format, encryption_algorithm)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                        c"__copy__",
                        {
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::noargs::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::noargs::Func =
                                    MlDsa65PrivateKey::__pymethod___copy____;
                            }
                            ::pyo3::impl_::trampoline::noargs::<Def>
                        },
                        c"__copy__($self)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"__deepcopy__",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PrivateKey::__pymethod___deepcopy____;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"__deepcopy__($self, _memo)\n--\n\n",
                    ),
                ),
            ],
            slots: &[],
        };
        &ITEMS
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PrivateKey {
    unsafe fn __pymethod_sign__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::sign;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PrivateKey as ::pyo3::PyClass>::NAME),
                func_name: "sign",
                positional_parameter_names: &["data", "context"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 1usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 2usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_1 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_2 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                ::pyo3::impl_::extract_argument::extract_pyclass_ref::<MlDsa65PrivateKey>(
                    unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                    &mut holder_2,
                )?,
                py,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "data",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument_with_default(
                        output[1usize],
                        &mut holder_1,
                        "context",
                        #[allow(
                            clippy::redundant_closure,
                            reason = "wrapping user-provided default expression"
                        )]
                        {
                            || ::pyo3::impl_::wrap::SomeWrap::wrap(None)
                        },
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod_public_key__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::public_key;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(::pyo3::impl_::extract_argument::extract_pyclass_ref::<
                MlDsa65PrivateKey,
            >(
                unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                &mut holder_0,
            )?);
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod_private_bytes_raw__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::private_bytes_raw;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                ::pyo3::impl_::extract_argument::extract_pyclass_ref::<MlDsa65PrivateKey>(
                    unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                    &mut holder_0,
                )?,
                py,
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod_private_bytes__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::private_bytes;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PrivateKey as ::pyo3::PyClass>::NAME),
                func_name: "private_bytes",
                positional_parameter_names: &["encoding", "format", "encryption_algorithm"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 3usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 3usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_1 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_2 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PrivateKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
                py,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "encoding",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[1usize],
                            )
                        },
                        &mut holder_1,
                        "format",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[2usize],
                            )
                        },
                        &mut holder_2,
                        "encryption_algorithm",
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod___copy____<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::__copy__;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PrivateKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod___deepcopy____<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PrivateKey::__deepcopy__;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PrivateKey as ::pyo3::PyClass>::NAME),
                func_name: "__deepcopy__",
                positional_parameter_names: &["_memo"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 1usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 1usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PrivateKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "_memo",
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
}
impl MlDsa65PublicKey {
    fn verify(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let valid = cryptography_openssl::mldsa::verify(
            &self.pkey,
            signature.as_bytes(),
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
impl MlDsa65PublicKey {
    #[allow(non_snake_case)]
    unsafe fn __pymethod___eq____(
        py: ::pyo3::Python<'_>,
        _slf: *mut ::pyo3::ffi::PyObject,
        arg0: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
        let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
        let mut holder_1 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
        let result = MlDsa65PublicKey::__eq__(
            match ::pyo3::impl_::extract_argument::extract_pyclass_ref::<MlDsa65PublicKey>(
                unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                &mut holder_0,
            ) {
                ::std::result::Result::Ok(value) => value,
                ::std::result::Result::Err(_) => {
                    return ::pyo3::impl_::callback::convert(py, py.NotImplemented());
                }
            },
            match {
                #[allow(unused_imports, reason = "`Probe` trait used on negative case only")]
                use ::pyo3::impl_::pyclass::Probe as _;
                ::pyo3::impl_::extract_argument::extract_argument(
                    unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, arg0) },
                    &mut holder_1,
                    "other",
                )
            } {
                ::std::result::Result::Ok(value) => value,
                ::std::result::Result::Err(_) => {
                    return ::pyo3::impl_::callback::convert(py, py.NotImplemented());
                }
            },
        );
        ::pyo3::impl_::callback::convert(py, result)
    }
}
impl ::pyo3::impl_::pyclass::PyClass__eq__SlotFragment<MlDsa65PublicKey>
    for ::pyo3::impl_::pyclass::PyClassImplCollector<MlDsa65PublicKey>
{
    #[inline]
    unsafe fn __eq__(
        self,
        py: ::pyo3::Python<'_>,
        _slf: *mut ::pyo3::ffi::PyObject,
        arg0: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        MlDsa65PublicKey::__pymethod___eq____(py, _slf, arg0)
    }
}
#[allow(unknown_lints, non_local_definitions)]
impl ::pyo3::impl_::pyclass::PyMethods<MlDsa65PublicKey>
    for ::pyo3::impl_::pyclass::PyClassImplCollector<MlDsa65PublicKey>
{
    fn py_methods(self) -> &'static ::pyo3::impl_::pyclass::PyClassItems {
        static ITEMS: ::pyo3::impl_::pyclass::PyClassItems = ::pyo3::impl_::pyclass::PyClassItems {
            methods: &[
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"verify",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PublicKey::__pymethod_verify__;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"verify($self, signature, data, context=None)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                        c"public_bytes_raw",
                        {
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::noargs::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::noargs::Func =
                                    MlDsa65PublicKey::__pymethod_public_bytes_raw__;
                            }
                            ::pyo3::impl_::trampoline::noargs::<Def>
                        },
                        c"public_bytes_raw($self)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"public_bytes",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PublicKey::__pymethod_public_bytes__;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"public_bytes($self, encoding, format)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::noargs(
                        c"__copy__",
                        {
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::noargs::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::noargs::Func =
                                    MlDsa65PublicKey::__pymethod___copy____;
                            }
                            ::pyo3::impl_::trampoline::noargs::<Def>
                        },
                        c"__copy__($self)\n--\n\n",
                    ),
                ),
                ::pyo3::impl_::pymethods::PyMethodDefType::Method(
                    ::pyo3::impl_::pymethods::PyMethodDef::fastcall_cfunction_with_keywords(
                        c"__deepcopy__",
                        {
                            struct Def;
                            impl ::pyo3::impl_::trampoline::MethodDef<
                                ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func,
                            > for Def {
                                const METH: ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::Func = MlDsa65PublicKey::__pymethod___deepcopy____;
                            }
                            ::pyo3::impl_::trampoline::fastcall_cfunction_with_keywords::<Def>
                        },
                        c"__deepcopy__($self, _memo)\n--\n\n",
                    ),
                ),
            ],
            slots: &[{
                #[allow(unknown_lints, non_local_definitions)]
                impl MlDsa65PublicKey {
                    #[expect(non_snake_case)]
                    unsafe fn __pymethod___richcmp____(
                        py: ::pyo3::Python<'_>,
                        slf: *mut ::pyo3::ffi::PyObject,
                        other: *mut ::pyo3::ffi::PyObject,
                        op: ::std::ffi::c_int,
                    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
                        use ::pyo3::class::basic::CompareOp;
                        use ::pyo3::impl_::pyclass::*;
                        let collector = PyClassImplCollector::<MlDsa65PublicKey>::new();
                        match CompareOp::from_raw(op).expect("invalid compareop") {
                            CompareOp::Lt => unsafe { collector.__lt__(py, slf, other) },
                            CompareOp::Le => unsafe { collector.__le__(py, slf, other) },
                            CompareOp::Eq => unsafe { collector.__eq__(py, slf, other) },
                            CompareOp::Ne => unsafe { collector.__ne__(py, slf, other) },
                            CompareOp::Gt => unsafe { collector.__gt__(py, slf, other) },
                            CompareOp::Ge => unsafe { collector.__ge__(py, slf, other) },
                        }
                    }
                }
                ::pyo3::ffi::PyType_Slot {
                    slot: ::pyo3::ffi::Py_tp_richcompare,
                    pfunc: {
                        type Cls = MlDsa65PublicKey;
                        ({
                            struct Def;
                            impl
                                ::pyo3::impl_::trampoline::MethodDef<
                                    ::pyo3::impl_::trampoline::richcmpfunc::Func,
                                > for Def
                            {
                                const METH: ::pyo3::impl_::trampoline::richcmpfunc::Func =
                                    Cls::__pymethod___richcmp____;
                            }
                            ::pyo3::impl_::trampoline::richcmpfunc::<Def>
                        }) as ::pyo3::ffi::richcmpfunc as _
                    },
                }
            }],
        };
        &ITEMS
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
impl MlDsa65PublicKey {
    unsafe fn __pymethod_verify__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PublicKey::verify;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PublicKey as ::pyo3::PyClass>::NAME),
                func_name: "verify",
                positional_parameter_names: &["signature", "data", "context"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 2usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 3usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_1 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_2 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_3 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                ::pyo3::impl_::extract_argument::extract_pyclass_ref::<MlDsa65PublicKey>(
                    unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                    &mut holder_3,
                )?,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "signature",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[1usize],
                            )
                        },
                        &mut holder_1,
                        "data",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument_with_default(
                        output[2usize],
                        &mut holder_2,
                        "context",
                        #[allow(
                            clippy::redundant_closure,
                            reason = "wrapping user-provided default expression"
                        )]
                        {
                            || ::pyo3::impl_::wrap::SomeWrap::wrap(None)
                        },
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod_public_bytes_raw__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PublicKey::public_bytes_raw;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                ::pyo3::impl_::extract_argument::extract_pyclass_ref::<MlDsa65PublicKey>(
                    unsafe { ::pyo3::impl_::extract_argument::cast_function_argument(py, _slf) },
                    &mut holder_0,
                )?,
                py,
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod_public_bytes__<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PublicKey::public_bytes;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PublicKey as ::pyo3::PyClass>::NAME),
                func_name: "public_bytes",
                positional_parameter_names: &["encoding", "format"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 2usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 2usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let mut holder_1 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PublicKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
                py,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "encoding",
                    )?
                },
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[1usize],
                            )
                        },
                        &mut holder_1,
                        "format",
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod___copy____<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PublicKey::__copy__;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PublicKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
    unsafe fn __pymethod___deepcopy____<'py>(
        py: ::pyo3::Python<'py>,
        _slf: *mut ::pyo3::ffi::PyObject,
        _args: *const *mut ::pyo3::ffi::PyObject,
        _nargs: ::pyo3::ffi::Py_ssize_t,
        _kwnames: *mut ::pyo3::ffi::PyObject,
    ) -> ::pyo3::PyResult<*mut ::pyo3::ffi::PyObject> {
        let function = MlDsa65PublicKey::__deepcopy__;
        const DESCRIPTION: ::pyo3::impl_::extract_argument::FunctionDescription =
            ::pyo3::impl_::extract_argument::FunctionDescription {
                cls_name: ::std::option::Option::Some(<MlDsa65PublicKey as ::pyo3::PyClass>::NAME),
                func_name: "__deepcopy__",
                positional_parameter_names: &["_memo"],
                positional_only_parameters: 0usize,
                required_positional_parameters: 1usize,
                keyword_only_parameters: &[],
            };
        let mut output = [::std::option::Option::None; 1usize];
        let (_args, _kwargs) = DESCRIPTION
            .extract_arguments_fastcall::<
                ::pyo3::impl_::extract_argument::NoVarargs,
                ::pyo3::impl_::extract_argument::NoVarkeywords,
            >(py, _args, _nargs, _kwnames, &mut output)?;
        let result = {
            #[allow(clippy::let_unit_value, reason = "many holders are just `()`")]
            let mut holder_0 = ::pyo3::impl_::extract_argument::FunctionArgumentHolder::INIT;
            let ret = function(
                unsafe { ::pyo3::impl_::pymethods::BoundRef::ref_from_ptr(py, &_slf) }
                    .cast::<MlDsa65PublicKey>()
                    .map_err(::std::convert::Into::<::pyo3::PyErr>::into)
                    .and_then(
                        #[allow(
                            clippy::unnecessary_fallible_conversions,
                            reason = "anything implementing `TryFrom<BoundRef>` is permitted"
                        )]
                        |bound| {
                            ::std::convert::TryFrom::try_from(bound)
                                .map_err(::std::convert::Into::into)
                        },
                    )?,
                {
                    #[allow(
                        unused_imports,
                        reason = "`Probe` trait used on negative case only"
                    )]
                    use ::pyo3::impl_::pyclass::Probe as _;
                    ::pyo3::impl_::extract_argument::extract_argument(
                        unsafe {
                            ::pyo3::impl_::extract_argument::unwrap_required_argument(
                                output[0usize],
                            )
                        },
                        &mut holder_0,
                        "_memo",
                    )?
                },
            );
            {
                let result = {
                    let obj = ret;
                    #[allow(
                        clippy::useless_conversion,
                        reason = "needed for Into<PyErr> conversion, may be redundant"
                    )]
                    ::pyo3::impl_::wrap::converter(&obj)
                        .wrap(obj)
                        .map_err(::core::convert::Into::<::pyo3::PyErr>::into)
                };
                ::pyo3::impl_::wrap::converter(&result).map_into_ptr(py, result)
            }
        };
        result
    }
}
pub(crate) mod mldsa {
    use super::{
        from_public_bytes, from_seed_bytes, generate_key, MlDsa65PrivateKey, MlDsa65PublicKey,
    };
    #[doc(hidden)]
    pub const __PYO3_NAME: &'static ::std::ffi::CStr = c"mldsa";
    #[doc(hidden)]
    pub(super) struct ModuleExec;
    #[doc(hidden)]
    pub static _PYO3_DEF: ::pyo3::impl_::pymodule::ModuleDef = {
        use ::pyo3::impl_::pymodule as impl_;
        unsafe extern "C" fn __pyo3_module_exec(
            module: *mut ::pyo3::ffi::PyObject,
        ) -> ::std::os::raw::c_int {
            ::pyo3::impl_::trampoline::module_exec(module, __pyo3_pymodule)
        }
        static SLOTS: impl_::PyModuleSlots<4> = impl_::PyModuleSlotsBuilder::new()
            .with_mod_exec(__pyo3_module_exec)
            .with_gil_used(false)
            .build();
        impl_::ModuleDef::new(__PYO3_NAME, c"", &SLOTS)
    };
    /// This autogenerated function is called by the python interpreter when importing
    /// the module.
    #[doc(hidden)]
    #[export_name = "PyInit_mldsa"]
    pub unsafe extern "C" fn __pyo3_init() -> *mut ::pyo3::ffi::PyObject {
        _PYO3_DEF.init_multi_phase()
    }
    fn __pyo3_pymodule(
        module: &::pyo3::Bound<'_, ::pyo3::types::PyModule>,
    ) -> ::pyo3::PyResult<()> {
        use ::pyo3::impl_::pymodule::PyAddToModule;
        from_public_bytes::_PYO3_DEF.add_to_module(module)?;
        from_seed_bytes::_PYO3_DEF.add_to_module(module)?;
        generate_key::_PYO3_DEF.add_to_module(module)?;
        MlDsa65PrivateKey::_PYO3_DEF.add_to_module(module)?;
        MlDsa65PublicKey::_PYO3_DEF.add_to_module(module)?;
        ::std::result::Result::Ok(())
    }
}
