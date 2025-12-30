from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass

from core.wallet.keys.public_hdnode import PublicHDNode
from core.wallet.keys.secp256k1 import tweak_add_pubkey, N


class PublicDerivationError(ValueError):
    pass


HARDENED_OFFSET = 0x80000000


def _ser32(i: int) -> bytes:
    return int(i).to_bytes(4, "big")


def derive_child_public(parent: PublicHDNode, index: int) -> PublicHDNode:
    """
    BIP32 public child derivation (non-hardened only).

    child_pub = parent_pub + (IL * G)
    child_chain = IR

    Data = serP(parent_pubkey) || ser32(index)
    I = HMAC-SHA512(key=parent_chaincode, data=Data)
    IL = I[0:32], IR = I[32:64]
    """
    if index < 0 or index > 0xFFFFFFFF:
        raise PublicDerivationError("index out of range")
    if index >= HARDENED_OFFSET:
        raise PublicDerivationError("cannot derive hardened child from public node")

    data = parent.public_key + _ser32(index)
    I = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    il_int = int.from_bytes(IL, "big")
    if il_int <= 0 or il_int >= N:
        raise PublicDerivationError("invalid IL for public derivation")

    child_pub = tweak_add_pubkey(parent.public_key, IL, compressed=True)

    return PublicHDNode(
        chain_code=IR,
        public_key=child_pub,
        depth=parent.depth + 1,
        child_num=index,
        parent_fingerprint=parent.fingerprint(),
        path=f"{parent.path}/{index}",
    )
