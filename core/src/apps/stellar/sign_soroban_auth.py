from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

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

    from apps.common import paths, seed

    from . import helpers, layout, writers

    await paths.validate_path(keychain, msg.address_n)

    node = keychain.derive(msg.address_n)
    pubkey = seed.remove_ed25519_prefix(node.public_key())

    w = bytearray()

    # ---------------------------------
    # INIT
    # ---------------------------------
    network_passphrase_hash = sha256(msg.network_passphrase.encode()).digest()
    writers.write_bytes_fixed(w, network_passphrase_hash, 32)

    address = helpers.address_from_public_key(pubkey)

    # confirm init
    await layout.require_confirm_init(address, msg.network_passphrase, False)

    # confirm auth info
    await layout.require_confirm_soroban_auth_info(
        msg.nonce, msg.signature_expiration_ledger
    )

    # confirm invocation
    await layout.require_confirm_soroban_invocation([], msg.invocation)

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
