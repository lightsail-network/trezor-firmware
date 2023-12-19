from typing import TYPE_CHECKING

import apps.common.writers as writers
from trezor.wire import DataError

# Reexporting to other modules
write_bytes_fixed = writers.write_bytes_fixed
write_uint32 = writers.write_uint32_be
write_uint64 = writers.write_uint64_be

if TYPE_CHECKING:
    from typing import AnyStr

    from trezor.utils import Writer
    from trezor.messages import (
        StellarSCValType,
        StellarSCVal,
        StellarSorobanAuthorizedFunction,
        StellarSorobanAuthorizedInvocation,
    )



def write_string(w: Writer, s: AnyStr) -> None:
    """Write XDR string padded to a multiple of 4 bytes."""
    # NOTE: 2 bytes smaller than if-else
    buf = s.encode() if isinstance(s, str) else s
    write_uint32(w, len(buf))
    writers.write_bytes_unchecked(w, buf)
    # if len isn't a multiple of 4, add padding bytes
    remainder = len(buf) % 4
    if remainder:
        writers.write_bytes_unchecked(w, bytes([0] * (4 - remainder)))


def write_bool(w: Writer, val: bool) -> None:
    # NOTE: 10 bytes smaller than if-else
    write_uint32(w, 1 if val else 0)


def write_pubkey(w: Writer, address: str) -> None:
    from .helpers import public_key_from_address

    # first 4 bytes of an address are the type, there's only one type (0)
    write_uint32(w, 0)
    writers.write_bytes_fixed(w, public_key_from_address(address), 32)

# def write_sc_val(w: Writer, val: StellarSCVal) -> None:
#     if val.type == StellarSCValType.SCV_BOOL:
#         write_bool(w, val.bool)
#     elif val.type == StellarSCValType.SCV_VOID:
#         pass # nothing to write
#     elif val.type == StellarSCValType.SCV_ERROR:
#         raise DataError(f"Stellar: Unsupported SCV type: {val.type}")
#     elif val.type == StellarSCValType.SCV_U32:
#         write_uint32(w, val.u32)
#     elif val.type == StellarSCValType.SCV_I32:
#         await confirm_sc_val("int32", str(val.i32))
#     elif val.type == StellarSCValType.SCV_U64:
#         write_uint64(w, val.u64)
#     elif val.type == StellarSCValType.SCV_I64:
#         await confirm_sc_val("int64", str(val.i64))
#     elif val.type == StellarSCValType.SCV_TIMEPOINT:
#         write_uint64(w, val.timepoint)
#     elif val.type == StellarSCValType.SCV_DURATION:
#         write_uint64(w, val.duration)
#     elif val.type == StellarSCValType.SCV_U128:
#         assert val.u128
#         value_bytes = val.u128.hi.to_bytes(
#             8, "big", signed=False
#         ) + val.u128.lo.to_bytes(8, "big", signed=False)
#         v = int.from_bytes(value_bytes, "big", signed=False)
#         await confirm_sc_val("uint128", str(v))
#     elif val.type == StellarSCValType.SCV_I128:
#         assert val.i128
#         value_bytes = val.i128.hi.to_bytes(
#             8, "big", signed=True
#         ) + val.i128.lo.to_bytes(8, "big", signed=False)
#         v = int.from_bytes(value_bytes, "big", signed=True)
#         await confirm_sc_val("int128", str(v))
#     elif val.type == StellarSCValType.SCV_U256:
#         assert val.u256
#         value_bytes = (
#             val.u256.hi_hi.to_bytes(8, "big", signed=False)
#             + val.u256.hi_lo.to_bytes(8, "big", signed=False)
#             + val.u256.lo_hi.to_bytes(8, "big", signed=False)
#             + val.u256.lo_lo.to_bytes(8, "big", signed=False)
#         )
#         v = int.from_bytes(value_bytes, "big", signed=False)
#         await confirm_sc_val("uint256", str(v))
#     elif val.type == StellarSCValType.SCV_I256:
#         assert val.i256
#         value_bytes = (
#             val.i256.hi_hi.to_bytes(8, "big", signed=True)
#             + val.i256.hi_lo.to_bytes(8, "big", signed=False)
#             + val.i256.lo_hi.to_bytes(8, "big", signed=False)
#             + val.i256.lo_lo.to_bytes(8, "big", signed=False)
#         )
#         v = int.from_bytes(value_bytes, "big", signed=True)
#         await confirm_sc_val("int256", str(v))
#     elif val.type == StellarSCValType.SCV_BYTES:
#         assert val.bytes is not None
#         await confirm_blob("confirm_sc_val", title, val.bytes, "val(bytes):")
#     elif val.type == StellarSCValType.SCV_STRING:
#         assert val.string is not None
#         await confirm_sc_val("string", val.string)
#     elif val.type == StellarSCValType.SCV_SYMBOL:
#         assert val.symbol is not None
#         await confirm_sc_val("symbol", val.symbol)
#     elif val.type == StellarSCValType.SCV_VEC:
#         if await should_show_more(
#             title,
#             ((ui.NORMAL, f"{title} contains {len(val.vec)} elements"),),
#             "Show full vec",
#             "should_show_vec",
#         ):
#             for idx, item in enumerate(val.vec):
#                 await require_confirm_sc_val(parent_objects + [str(idx)], item)
#     elif val.type == StellarSCValType.SCV_MAP:
#         if await should_show_more(
#             title,
#             ((ui.NORMAL, f"{title} contains {len(val.ma)} items"),),
#             "Show full map",
#             "should_show_map",
#         ):
#             for idx, item in enumerate(val.map):
#                 assert item.key
#                 assert item.value
#                 await require_confirm_sc_val(
#                     parent_objects + [str(idx), "key"], item.key
#                 )
#                 await require_confirm_sc_val(
#                     parent_objects + [str(idx), "value"], item.value
#                 )
#     elif val.type == StellarSCValType.SCV_ADDRESS:
#         assert val.address
#         await confirm_sc_val("address", val.address.address)
#     elif val.type == StellarSCValType.SCV_CONTRACT_INSTANCE:
#         assert val.instance
#         props: list[tuple[str, str]] = [("val type:", "contract instance")]
#         if val.instance.executable.type == StellarContractExecutableType.CONTRACT_EXECUTABLE_WASM:
#             assert val.instance.executable
#             assert val.instance.executable.wasm_hash
#             props.append(("executable.type", "CONTRACT_EXECUTABLE_WASM"))
#             props.append(
#                 (
#                     "executable.wasm_hash",
#                     ubinascii.hexlify(val.instance.executable.wasm_hash).decode(
#                         "utf-8"
#                     ),
#                 )
#             )
#             pass
#         elif val.instance.executable.type == StellarContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET:
#             props.append(("executable.type", "CONTRACT_EXECUTABLE_STELLAR_ASSET"))
#             pass
#         else:
#             raise DataError(
#                 f"Stellar: Unsupported executable type: {val.instance.executable.type}"
#             )

#         await layouts.confirm_properties("confirm_sc_val", title, props)

#         if await should_show_more(
#             title,
#             ((ui.NORMAL, f"{title} contains storage"),),
#             "Show full storage",
#             "should_show_storage",
#         ):
#             for idx, item in enumerate(val.instance.storage):
#                 assert item.key
#                 assert item.value
#                 await require_confirm_sc_val(
#                     parent_objects + [str(idx), "storage", "key"], item.key
#                 )
#                 await require_confirm_sc_val(
#                     parent_objects + [str(idx), "storage", "value"], item.value
#                 )
#     elif val.type == StellarSCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE:
#         await confirm_sc_val("ledger key contract instance", "[no content]")
#     elif val.type == StellarSCValType.SCV_LEDGER_KEY_NONCE:
#         await confirm_sc_val("ledger key nonce", str(val.nonce_key))
#     else:
#         raise DataError(f"Stellar: Unsupported SCV type: {val.type}")