.. hazmat::

SLH-DSA signing
===============

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.slhdsa


`SLH-DSA`_ (Stateless Hash-Based Digital Signature Algorithm) is a
post-quantum digital signature scheme standardized in `FIPS 205`_. It is
based entirely on hash functions.

.. note::

    SLH-DSA support is available only when using a backend that implements it.

.. class:: SlhDsaParameterSet

    .. versionadded:: 47.0.0

    An enumeration of SLH-DSA parameter sets.

    .. attribute:: SHAKE_256F

        The SLH-DSA-SHAKE-256f parameter set. This uses SHAKE-256 as the
        underlying hash function, with the "f" (fast) signing variant.

Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric.slhdsa import (
    ...     SlhDsa256PrivateKey, SlhDsaParameterSet
    ... )
    >>> private_key = SlhDsa256PrivateKey.generate(
    ...     SlhDsaParameterSet.SHAKE_256F
    ... )
    >>> signature = private_key.sign(b"my authenticated message")
    >>> public_key = private_key.public_key()
    >>> # Raises InvalidSignature if verification fails
    >>> public_key.verify(signature, b"my authenticated message")

SLH-DSA also supports an optional context string (up to 255 bytes) that
is bound to the signature:

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric.slhdsa import (
    ...     SlhDsa256PrivateKey, SlhDsaParameterSet
    ... )
    >>> private_key = SlhDsa256PrivateKey.generate(
    ...     SlhDsaParameterSet.SHAKE_256F
    ... )
    >>> signature = private_key.sign(
    ...     b"my authenticated message",
    ...     context=b"my context",
    ... )
    >>> public_key = private_key.public_key()
    >>> public_key.verify(
    ...     signature, b"my authenticated message", context=b"my context"
    ... )

Key interfaces
~~~~~~~~~~~~~~

.. class:: SlhDsa256PrivateKey

    .. versionadded:: 47.0.0

    .. classmethod:: generate(parameter_set)

        Generate an SLH-DSA private key.

        :param parameter_set: The parameter set to use.
        :type parameter_set: :class:`SlhDsaParameterSet`

        :returns: :class:`SlhDsa256PrivateKey`

    .. classmethod:: from_private_bytes(parameter_set, data)

        :param parameter_set: The parameter set to use.
        :type parameter_set: :class:`SlhDsaParameterSet`

        :param data: The private key bytes (128 bytes for
            :attr:`SlhDsaParameterSet.SHAKE_256F`).
        :type data: :term:`bytes-like`

        :returns: :class:`SlhDsa256PrivateKey`

        :raises ValueError: This is raised if the private key data is
            not the correct length.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import slhdsa
            >>> private_key = slhdsa.SlhDsa256PrivateKey.generate(
            ...     slhdsa.SlhDsaParameterSet.SHAKE_256F
            ... )
            >>> private_bytes = private_key.private_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PrivateFormat.Raw,
            ...     encryption_algorithm=serialization.NoEncryption()
            ... )
            >>> loaded_private_key = slhdsa.SlhDsa256PrivateKey.from_private_bytes(
            ...     slhdsa.SlhDsaParameterSet.SHAKE_256F, private_bytes
            ... )

    .. attribute:: parameter_set

        :type: :class:`SlhDsaParameterSet`

        The parameter set used by this key.

    .. method:: public_key()

        :returns: :class:`SlhDsa256PublicKey`

    .. method:: sign(data, context=None)

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :param context: Optional context to bind to the signature (maximum
            255 bytes). If ``None``, an empty context is used.
        :type context: :term:`bytes-like` or ``None``

        :returns bytes: The signature (49856 bytes for
            :attr:`SlhDsaParameterSet.SHAKE_256F`).

        :raises ValueError: This is raised if the context is longer than
            255 bytes.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`)
        and format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

    .. method:: private_bytes_raw()

        .. versionadded:: 47.0.0

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`private_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding,
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        format, and
        :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`.

        :return bytes: Raw key.

.. class:: SlhDsa256PublicKey

    .. versionadded:: 47.0.0

    .. classmethod:: from_public_bytes(parameter_set, data)

        :param parameter_set: The parameter set to use.
        :type parameter_set: :class:`SlhDsaParameterSet`

        :param bytes data: The public key bytes (64 bytes for
            :attr:`SlhDsaParameterSet.SHAKE_256F`).

        :returns: :class:`SlhDsa256PublicKey`

        :raises ValueError: This is raised if the public key data is
            not the correct length.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import slhdsa
            >>> private_key = slhdsa.SlhDsa256PrivateKey.generate(
            ...     slhdsa.SlhDsaParameterSet.SHAKE_256F
            ... )
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = slhdsa.SlhDsa256PublicKey.from_public_bytes(
            ...     slhdsa.SlhDsaParameterSet.SHAKE_256F, public_bytes
            ... )

    .. attribute:: parameter_set

        :type: :class:`SlhDsaParameterSet`

        The parameter set used by this key.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`)
        and format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum.

        :returns bytes: The public key bytes.

    .. method:: public_bytes_raw()

        .. versionadded:: 47.0.0

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`public_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding and
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format.

        :return bytes: Raw key.

    .. method:: verify(signature, data, context=None)

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :param context: Optional context that was bound to the signature
            (maximum 255 bytes). If ``None``, an empty context is used.
        :type context: :term:`bytes-like` or ``None``

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.

        :raises ValueError: This is raised if the context is longer than
            255 bytes.


.. _`SLH-DSA`: https://en.wikipedia.org/wiki/SPHINCS
.. _`FIPS 205`: https://csrc.nist.gov/pubs/fips/205/final
