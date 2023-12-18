from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain
from trezor import log

if TYPE_CHECKING:
    from trezor.messages import StellarSignedTx, StellarSignSorobanAuthorization

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def sign_soroban_auth(
    msg: StellarSignSorobanAuthorization, keychain: Keychain
) -> StellarSignedTx:
    from trezor.crypto.curve import ed25519
    from trezor.crypto.hashlib import sha256
    from trezor.messages import StellarSignedTx
    from trezor.wire import DataError, ProcessError
    from trezor.wire.context import call_any

    from apps.common import paths, seed

    from . import consts, helpers, layout, writers

    await paths.validate_path(keychain, msg.address_n)

    node = keychain.derive(msg.address_n)
    pubkey = seed.remove_ed25519_prefix(node.public_key())

    w = bytearray()

    # ---------------------------------
    # INIT
    # ---------------------------------
    network_passphrase_hash = sha256(msg.network_passphrase.encode()).digest()
    writers.write_bytes_fixed(w, network_passphrase_hash, 32)

    # ---------------------------------
    # FINAL
    # ---------------------------------
    # 4 null bytes representing a (currently unused) empty union
    writers.write_uint32(w, 0)
    # final confirm
    # await layout.require_confirm_final(100, 1)

    # sign
    digest = sha256(w).digest()
    signature = ed25519.sign(node.private_key(), digest)

    # Add the public key for verification that the right account was used for signing
    return StellarSignedTx(public_key=pubkey, signature=signature)
