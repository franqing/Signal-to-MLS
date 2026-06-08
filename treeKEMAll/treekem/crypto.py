"""
密码学原语：HKDF 密钥派生与模拟 HPKE 封装。

MLS 使用 HPKE 加密 path_secret；本实验用 AES-GCM + HKDF 模拟，
保持「仅持有目标节点私钥者可解密」这一 TreeKEM 安全不变量。
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

_BACKEND = default_backend()
_HASH_LEN = 32


def derive_secret(secret: bytes, label: str) -> bytes:
    """RFC 9420 DeriveSecret：HKDF-Expand-Label(secret, label, "", Hash.Length)"""
    info = _hkdf_label(label, b"", _HASH_LEN)
    return HKDFExpand(algorithm=hashes.SHA256(), length=_HASH_LEN, info=info, backend=_BACKEND).derive(secret)


def _hkdf_label(label: str, context: bytes, length: int) -> bytes:
    return b"MLS 1.0 " + _encode_length(label.encode()) + _encode_length(context) + length.to_bytes(2, "big")


def _encode_length(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


@dataclass(frozen=True)
class KeyPair:
    private_key: bytes
    public_key: bytes

    @classmethod
    def generate(cls, node_secret: bytes) -> KeyPair:
        """KEM.DeriveKeyPair(node_secret) — 用 node_secret 播种 X25519"""
        seed = derive_secret(node_secret, "node_kem_seed")
        private = x25519.X25519PrivateKey.from_private_bytes(seed[:32])
        public = private.public_key()
        return cls(
            private_key=private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            public_key=public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )


def encrypt_path_secret(recipient_pub: bytes, path_secret: bytes, group_context: bytes) -> bytes:
    """模拟 EncryptWithLabel(pk, "UpdatePathNode", group_context, path_secret)"""
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pub))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"UpdatePathNode" + group_context,
        backend=_BACKEND,
    ).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, path_secret, b"")
    eph_pub = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return eph_pub + nonce + ct


def decrypt_path_secret(recipient_priv: bytes, ciphertext: bytes, group_context: bytes) -> bytes:
    eph_pub = ciphertext[:32]
    nonce = ciphertext[32:44]
    ct = ciphertext[44:]
    shared = x25519.X25519PrivateKey.from_private_bytes(recipient_priv).exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"UpdatePathNode" + group_context,
        backend=_BACKEND,
    ).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, b"")


def epoch_secret_from_root(path_secret_at_root: bytes, group_context: bytes) -> bytes:
    """从根节点 path_secret 派生 epoch 密钥（简化版 key schedule 终点）"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"epoch" + group_context,
        backend=_BACKEND,
    ).derive(path_secret_at_root)
