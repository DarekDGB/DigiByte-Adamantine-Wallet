from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol, Tuple

from core.wallet.account import WalletAccount
from core.wallet.state import WalletState
from core.wallet.tx.models import UnsignedTransaction


class SigningError(ValueError):
    pass


class Signer(Protocol):
    """
    Signing primitive boundary.

    Later this will do real ECDSA over a real transaction sighash.
    For now it signs a deterministic placeholder message.
    """

    def sign(self, message: bytes, privkey32: bytes) -> bytes: ...


@dataclass(frozen=True)
class SignedInput:
    """
    Placeholder signed input material.

    Later: scriptSig / witness / sighash type, etc.
    """
    signature: bytes
    pubkey: bytes


@dataclass(frozen=True)
class SignedTransaction:
    unsigned: UnsignedTransaction
    signed_inputs: List[SignedInput]


def _extract_privkey_bytes(node) -> bytes:
    """
    Accept both node styles:
    - node.private_key: bytes
    - node.private_key_hex: str
    """
    priv = getattr(node, "private_key", None)
    if isinstance(priv, (bytes, bytearray)):
        b = bytes(priv)
        if len(b) != 32:
            raise SigningError("private_key must be 32 bytes")
        return b

    priv_hex = getattr(node, "private_key_hex", None)
    if isinstance(priv_hex, str) and priv_hex:
        try:
            b = bytes.fromhex(priv_hex)
        except ValueError as e:
            raise SigningError("private_key_hex is not valid hex") from e
        if len(b) != 32:
            raise SigningError("private_key_hex must decode to 32 bytes")
        return b

    raise SigningError("node has no private key (watch-only)")


def _find_address_path(
    account: WalletAccount,
    address: str,
    *,
    state: WalletState,
    max_scan: int,
) -> Tuple[str, int]:
    """
    Brute-force find whether an address belongs to:
    - receive chain (0) or change chain (1),
    and return (chain, index).

    This is CI-safe + deterministic and avoids needing an address index map yet.
    Later we’ll replace this with a proper address index cache.
    """
    scan_limit = min(max_scan, max(state.gap_limit * 10, state.gap_limit))

    for i in range(scan_limit):
        if account.receive_address_at(i) == address:
            return ("receive", i)
        if account.change_address_at(i) == address:
            return ("change", i)

    raise SigningError("cannot locate address in account (scan limit exceeded)")


def _derive_node_for_chain_index(account: WalletAccount, chain: str, index: int):
    if chain == "receive":
        return account.derive_receive_node(index)
    if chain == "change":
        return account.derive_change_node(index)
    raise SigningError("invalid chain")


def _placeholder_sighash(unsigned: UnsignedTransaction, input_index: int) -> bytes:
    """
    Placeholder message to sign (NOT a real transaction sighash).
    We only need this to prove the signing boundary works.

    Later: replace with legacy SIGHASH_ALL over serialized tx.
    """
    base = f"adamantine:sighash:v0:{input_index}:{unsigned.fee_sats}:{len(unsigned.inputs)}:{len(unsigned.outputs)}"
    return base.encode("utf-8")


def sign_transaction_p2pkh(
    *,
    unsigned: UnsignedTransaction,
    account: WalletAccount,
    state: WalletState,
    signer: Signer,
    max_scan: int = 2000,
) -> SignedTransaction:
    """
    Sign each input using keys derived from the account.

    Security rules:
    - If we cannot extract a private key for any required node -> fail loudly.
    - Watch-only will fail by design.

    NOTE: This produces placeholder SignedInput objects for now.
    """
    signed_inputs: List[SignedInput] = []

    for idx, txin in enumerate(unsigned.inputs):
        chain, i = _find_address_path(account, txin.address, state=state, max_scan=max_scan)
        node = _derive_node_for_chain_index(account, chain, i)

        priv = _extract_privkey_bytes(node)

        # pubkey bytes are derived from privkey via secp module
        from core.wallet.keys.secp256k1 import pubkey_from_privkey

        pubkey = pubkey_from_privkey(priv, compressed=True)
        msg = _placeholder_sighash(unsigned, idx)
        sig = signer.sign(msg, priv)

        signed_inputs.append(SignedInput(signature=sig, pubkey=pubkey))

    return SignedTransaction(unsigned=unsigned, signed_inputs=signed_inputs)
