from typing import Optional

from ubinascii import hexlify

from trezor.crypto.curve import ed25519
from trezor.crypto.hashlib import sha256
from trezor.messages import StellarSignTxV0, StellarSignTxV1, StellarSignedTx, StellarTxV1, StellarTxV1Request, StellarTimeBounds, StellarTxOpRequest, StellarSignTx, StellarMemo, StellarMuxedAccount
from trezor.wire import ProcessError

from apps.common import paths, seed
from apps.common.keychain import auto_keychain

from . import consts, helpers, layout, writers
from .operations import process_operation


# @auto_keychain(__name__)
# async def sign_tx_v0(ctx, msg: StellarSignTxV0, keychain):
#     await paths.validate_path(ctx, keychain, msg.address_n)
#
#     node = keychain.derive(msg.address_n)
#     pubkey = seed.remove_ed25519_prefix(node.public_key())
#
#     if msg.num_operations == 0:
#         raise ProcessError("Stellar: At least one operation is required")
#
#     w = bytearray()
#     await _init(ctx, w, pubkey, msg)
#     await _timebounds(ctx, w, msg.timebounds_start, msg.timebounds_end)
#     await _memo(ctx, w, msg)
#     await _operations(ctx, w, msg.num_operations)
#     await _final(ctx, w, msg)
#
#     # sign
#     digest = sha256(w).digest()
#     signature = ed25519.sign(node.private_key(), digest)
#
#     # Add the public key for verification that the right account was used for signing
#     return StellarSignedTx(public_key=pubkey, signature=signature)

@auto_keychain(__name__)
async def sign_tx_v1(ctx, msg: StellarSignTxV1, keychain):
    await paths.validate_path(ctx, keychain, msg.address_n)

    node = keychain.derive(msg.address_n)
    pubkey = seed.remove_ed25519_prefix(node.public_key())
    network_passphrase = msg.network_passphrase

    tx_msg: StellarTxV1 = await ctx.call(StellarTxV1Request(), StellarTxV1)

    if tx_msg.num_operations == 0:
        raise ProcessError("Stellar: At least one operation is required")

    w = bytearray()
    await _init(ctx, w, pubkey, network_passphrase, tx_msg)
    await _timebounds(ctx, w, tx_msg.time_bounds)
    await _memo(ctx, w, tx_msg.memo)
    await _operations(ctx, w, tx_msg.num_operations)
    await _final(ctx, w, tx_msg)

    # sign
    digest = sha256(w).digest()
    signature = ed25519.sign(node.private_key(), digest)

    # Add the public key for verification that the right account was used for signing
    return StellarSignedTx(public_key=pubkey, signature=signature)


async def _final(ctx, w: bytearray, msg: StellarSignTx):
    # 4 null bytes representing a (currently unused) empty union
    writers.write_uint32(w, 0)
    # final confirm
    await layout.require_confirm_final(ctx, msg.fee, msg.num_operations)


async def _init(ctx, w: bytearray, pubkey: bytes, network_passphrase: str, tx_msg: StellarTxV1):
    network_passphrase_hash = sha256(network_passphrase).digest()
    writers.write_bytes_fixed(w, network_passphrase_hash, 32)
    writers.write_bytes_fixed(w, consts.TX_V1_TYPE, 4)

    address = helpers.address_from_public_key(pubkey)
    accounts_match = tx_msg.source_account.ed25519_account == address

    writers.write_muxed_account(w, tx_msg.source_account)
    writers.write_uint32(w, tx_msg.fee)
    writers.write_uint64(w, tx_msg.sequence_number)

    # confirm init
    await layout.require_confirm_init(
        ctx, tx_msg.source_account.ed25519_account, network_passphrase, accounts_match
    )




async def _timebounds(ctx, w: bytearray, time_bounds: Optional[StellarTimeBounds]):
    if time_bounds:
        # confirm dialog
        await layout.require_confirm_timebounds(ctx, time_bounds.min_time, time_bounds.max_time)
        writers.write_bool(w, True)

        # timebounds are sent as uint32s since that's all we can display, but they must be hashed as 64bit
        # TODO: fix it in display
        writers.write_uint64(w, time_bounds.min_time)
        writers.write_uint64(w, time_bounds.max_time)
    else:
        writers.write_bool(w, False)


async def _operations(ctx, w: bytearray, num_operations: int):
    writers.write_uint32(w, num_operations)
    for i in range(num_operations):
        op = await ctx.call_any(StellarTxOpRequest(), *consts.op_wire_types)
        await process_operation(ctx, w, op)


async def _memo(ctx, w: bytearray, memo: StellarMemo):
    writers.write_uint32(w, memo.memo_type)
    if memo.memo_type == consts.MEMO_TYPE_NONE:
        # nothing is serialized
        memo_confirm_text = ""
    elif memo.memo_type == consts.MEMO_TYPE_TEXT:
        # Text: 4 bytes (size) + up to 28 bytes
        if len(memo.memo_text) > 28:
            raise ProcessError("Stellar: max length of a memo text is 28 bytes")
        writers.write_string(w, memo.memo_text)
        memo_confirm_text = memo.memo_text
    elif memo.memo_type == consts.MEMO_TYPE_ID:
        # ID: 64 bit unsigned integer
        writers.write_uint64(w, memo.memo_id)
        memo_confirm_text = str(memo.memo_id)
    elif memo.memo_type in (consts.MEMO_TYPE_HASH, consts.MEMO_TYPE_RETURN):
        # Hash/Return: 32 byte hash
        writers.write_bytes_fixed(w, bytearray(memo.memo_hash), 32)
        memo_confirm_text = hexlify(memo.memo_hash).decode()
    else:
        raise ProcessError("Stellar invalid memo type")
    await layout.require_confirm_memo(ctx, memo.memo_type, memo_confirm_text)
