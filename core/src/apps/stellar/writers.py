from typing import TYPE_CHECKING

import apps.common.writers as writers
from trezor.utils import ensure
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
        StellarContractExecutableType,
        StellarSCAddress,
        StellarSCAddressType,
    )


def _write_int(w: Writer, n: int, bits: int, bigendian: bool) -> int:
    ensure(-(2 ** (bits - 1)) <= n <= 2 ** (bits - 1) - 1, "overflow")
    shifts = range(0, bits, 8)
    if bigendian:
        shifts = reversed(shifts)
    for num in shifts:
        w.append((n >> num) & 0xFF)
    return bits // 8


def write_int32(w: Writer, n: int) -> int:
    return _write_int(w, n, 32, True)


def write_int64(w: Writer, n: int) -> int:
    return _write_int(w, n, 64, True)


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


def write_contract(w: Writer, contract: str) -> None:
    from .helpers import decode_contract

    writers.write_bytes_fixed(w, decode_contract(contract), 32)


def write_sc_address(w: Writer, address: StellarSCAddress) -> None:
    w.write_uint32(address.type)
    if address.type == StellarSCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
        write_pubkey(w, address.account)
    elif address.type == StellarSCAddressType.SC_ADDRESS_TYPE_CONTRACT:
        write_contract(w, address.contract)
    else:
        raise DataError(f"Stellar: Unsupported SC address type: {address.type}")


def write_sc_val(w: Writer, val: StellarSCVal) -> None:
    if val.type == StellarSCValType.SCV_BOOL:
        write_bool(w, val.bool)
    elif val.type == StellarSCValType.SCV_VOID:
        pass  # nothing to write
    elif val.type == StellarSCValType.SCV_ERROR:
        raise DataError(f"Stellar: Unsupported SCV type: {val.type}")
    elif val.type == StellarSCValType.SCV_U32:
        write_uint32(w, val.u32)
    elif val.type == StellarSCValType.SCV_I32:
        write_int32(w, val.i32)
    elif val.type == StellarSCValType.SCV_U64:
        write_uint64(w, val.u64)
    elif val.type == StellarSCValType.SCV_I64:
        write_int64(w, val.i64)
    elif val.type == StellarSCValType.SCV_TIMEPOINT:
        write_uint64(w, val.timepoint)
    elif val.type == StellarSCValType.SCV_DURATION:
        write_uint64(w, val.duration)
    elif val.type == StellarSCValType.SCV_U128:
        assert val.u128
        write_uint32(w, val.u128.hi)
        write_uint32(w, val.u128.lo)
    elif val.type == StellarSCValType.SCV_I128:
        assert val.i128
        write_int32(w, val.i128.hi)
        write_uint32(w, val.i128.lo)
    elif val.type == StellarSCValType.SCV_U256:
        assert val.u256
        write_uint64(w, val.u256.hi_hi)
        write_uint64(w, val.u256.hi_lo)
        write_uint64(w, val.u256.lo_hi)
        write_uint64(w, val.u256.lo_lo)
    elif val.type == StellarSCValType.SCV_I256:
        assert val.i256
        write_int64(w, val.i256.hi_hi)
        write_uint64(w, val.i256.hi_lo)
        write_uint64(w, val.i256.lo_hi)
        write_uint64(w, val.i256.lo_lo)
    elif val.type == StellarSCValType.SCV_BYTES:
        assert val.bytes is not None
        # if data len isn't a multiple of 4, add padding bytes
        write_bytes_fixed(
            w,
            val.bytes + bytes([0] * (4 - len(val.bytes) % 4)),
            len(val.bytes) + (4 - len(val.bytes) % 4),
        )
    elif val.type == StellarSCValType.SCV_STRING:
        write_string(w, val.string)
    elif val.type == StellarSCValType.SCV_SYMBOL:
        write_string(w, val.symbol)
    elif val.type == StellarSCValType.SCV_VEC:
        write_bool(w, True)
        write_uint32(w, len(val.vec))
        for item in val.vec:
            write_sc_val(w, item)
    elif val.type == StellarSCValType.SCV_MAP:
        write_bool(w, True)
        write_uint32(w, len(val.map))
        for item in val.map:
            write_sc_val(w, item.key)
            write_sc_val(w, item.value)
    elif val.type == StellarSCValType.SCV_ADDRESS:
        assert val.address
        write_sc_address(w, val.address)
    elif val.type == StellarSCValType.SCV_CONTRACT_INSTANCE:
        assert val.instance
        write_uint32(w, val.instance.type)
        if (
            val.instance.executable.type
            == StellarContractExecutableType.CONTRACT_EXECUTABLE_WASM
        ):
            assert val.instance.executable
            assert val.instance.executable.wasm_hash
            write_bytes_fixed(w, val.instance.executable.wasm_hash, 32)
        elif (
            val.instance.executable.type
            == StellarContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET
        ):
            pass  # nothing to write
        else:
            raise DataError(
                f"Stellar: Unsupported executable type: {val.instance.executable.type}"
            )
        if val.instance.storage:
            write_bool(w, True)
            write_uint32(w, len(val.instance.storage))
            for item in val.instance.storage:
                write_sc_val(w, item.key)
                write_sc_val(w, item.value)
        else:
            write_bool(w, False)
    elif val.type == StellarSCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE:
        pass  # nothing to write
    elif val.type == StellarSCValType.SCV_LEDGER_KEY_NONCE:
        write_int64(w, val.nonce)
    else:
        raise DataError(f"Stellar: Unsupported SCV type: {val.type}")
