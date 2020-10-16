# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from typing import Tuple, Optional
import base64
from enum import IntEnum
import secrets

import coincurve
from coincurve._libsecp256k1 import ffi, lib  # pylint: disable=no-name-in-module
from coincurve.context import GLOBAL_CONTEXT

from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder

from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

RECOMMENDED_RSA_PUBLIC_EXPONENT = 65537


class CryptoBoxCtx:
    def __init__(self, privk_path, pubk_path):
        with open(privk_path, "rb") as privk:
            self.privk = PrivateKey(
                load_pem_private_key(
                    privk.read(),
                    password=None,
                    backend=default_backend(),
                ).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
                RawEncoder,
            )

        with open(pubk_path, "rb") as pubk:
            self.pubk = PublicKey(
                load_pem_public_key(
                    pubk.read(),
                    backend=default_backend(),
                ).public_bytes(Encoding.Raw, PublicFormat.Raw),
                RawEncoder,
            )
        self.box = Box(self.privk, self.pubk)

    def encrypt(self, plain, nonce):
        return self.box.encrypt(plain, nonce)

    def decrypt(self, cipher, nonce):
        return self.box.decrypt(cipher, nonce)


# As per mbedtls md_type_t
class CCFDigestType(IntEnum):
    MD_NONE = 0
    MD_MD2 = 1
    MD_MD4 = 2
    MD_MD5 = 3
    MD_SHA1 = 4
    MD_SHA224 = 5
    MD_SHA256 = 6
    MD_SHA384 = 7
    MD_SHA512 = 8
    MD_RIPEMD160 = 9


# This function calls the native API and does not rely on the
# imported library's implementation. Though not being used by
# the current test, it might still be helpful to have this
# sequence of native calls for verification, in case the
# imported library's code changes.
def verify_recover_secp256k1_bc_native(
    signature, req, hasher=coincurve.utils.sha256, context=GLOBAL_CONTEXT
):
    # Compact
    native_rec_sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    raw_sig, recovery_id = signature[:64], coincurve.utils.bytes_to_int(signature[64:])
    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        context.ctx, native_rec_sig, raw_sig, recovery_id
    )

    # Recover public key
    native_public_key = ffi.new("secp256k1_pubkey *")
    msg_hash = hasher(req) if hasher is not None else req
    lib.secp256k1_ecdsa_recover(
        context.ctx, native_public_key, native_rec_sig, msg_hash
    )

    # Convert
    native_standard_sig = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        context.ctx, native_standard_sig, native_rec_sig
    )

    # Verify
    ret = lib.secp256k1_ecdsa_verify(
        context.ctx, native_standard_sig, msg_hash, native_public_key
    )
    return ret


def verify_recover_secp256k1_bc(
    signature, req, hasher=coincurve.utils.sha256, context=GLOBAL_CONTEXT
):
    msg_hash = hasher(req) if hasher is not None else req
    rec_sig = coincurve.ecdsa.deserialize_recoverable(signature)
    public_key = coincurve.PublicKey(coincurve.ecdsa.recover(req, rec_sig))
    n_sig = coincurve.ecdsa.recoverable_convert(rec_sig)

    if not lib.secp256k1_ecdsa_verify(
        context.ctx, n_sig, msg_hash, public_key.public_key
    ):
        raise RuntimeError("Failed to verify SECP256K1 bitcoin signature")


def verify_request_sig(raw_cert, sig, req, request_body, md):
    try:
        cert = load_der_x509_certificate(raw_cert, backend=default_backend())

        digest = (
            hashes.SHA256()
            if md == CCFDigestType.MD_SHA256
            else cert.signature_hash_algorithm
        )

        # verify that the digest matches the hash of the body
        h = hashes.Hash(digest, backend=default_backend())
        h.update(request_body)
        raw_req_digest = h.finalize()
        header_digest = base64.b64decode(req.decode().split("SHA-256=")[1])
        assert (
            header_digest == raw_req_digest
        ), "Digest header does not match request body"

        pub_key = cert.public_key()
        hash_alg = ec.ECDSA(digest)
        pub_key.verify(sig, req, hash_alg)
    except InvalidSignature as e:
        # we support a non-standard curve, which is also being
        # used for bitcoin.
        if pub_key._curve.name != "secp256k1":  # pylint: disable=protected-access
            raise e

        verify_recover_secp256k1_bc(sig, req)


def generate_aes_key(key_bits: int) -> bytes:
    return secrets.token_bytes(key_bits // 8)


def generate_rsa_keypair(key_size: int) -> Tuple[str, str]:
    priv = rsa.generate_private_key(
        public_exponent=RECOMMENDED_RSA_PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend(),
    )
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def unwrap_key_rsa_oaep(
    wrapped_key: bytes, wrapping_key_priv_pem: str, label: Optional[bytes]
) -> bytes:
    wrapping_key = load_pem_private_key(
        wrapping_key_priv_pem.encode("ascii"), None, default_backend()
    )
    unwrapped = wrapping_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label,
        ),
    )
    return unwrapped
