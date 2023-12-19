import ubinascii
from typing import TYPE_CHECKING

import trezor.ui.layouts as layouts
from trezor import strings, ui
from trezor.enums import (
    ButtonRequestType,
    StellarContractExecutableType,
    StellarSCValType,
    StellarSorobanAuthorizedFunctionType,
)
from trezor.ui.layouts import confirm_blob, should_show_more
from trezor.wire import DataError

from . import consts, helpers

if TYPE_CHECKING:
    from trezor.enums import StellarMemoType
    from trezor.messages import (
        StellarAsset,
        StellarSCVal,
        StellarSorobanAuthorizedFunction,
        StellarSorobanAuthorizedInvocation,
    )


async def require_confirm_init(
    address: str,
    network_passphrase: str,
    accounts_match: bool,
) -> None:
    description = "Initialize signing with" + (
        " your account" if accounts_match else ""
    )
    await layouts.confirm_address(
        "Confirm Stellar",
        address,
        description,
        "confirm_init",
    )

    # get_network_warning
    if network_passphrase == consts.NETWORK_PASSPHRASE_PUBLIC:
        network = None
    elif network_passphrase == consts.NETWORK_PASSPHRASE_TESTNET:
        network = "testnet network"
    else:
        network = "private network"

    if network:
        await layouts.confirm_metadata(
            "confirm_init_network",
            "Confirm network",
            "Transaction is on {}",
            network,
            ButtonRequestType.ConfirmOutput,
        )


async def require_confirm_timebounds(start: int, end: int) -> None:
    await layouts.confirm_properties(
        "confirm_timebounds",
        "Confirm timebounds",
        (
            (
                "Valid from (UTC)",
                strings.format_timestamp(start) if start > 0 else "[no restriction]",
            ),
            (
                "Valid to (UTC)",
                strings.format_timestamp(end) if end > 0 else "[no restriction]",
            ),
        ),
    )


async def require_confirm_memo(memo_type: StellarMemoType, memo_text: str) -> None:
    from trezor.enums import StellarMemoType

    if memo_type == StellarMemoType.TEXT:
        description = "Memo (TEXT)"
    elif memo_type == StellarMemoType.ID:
        description = "Memo (ID)"
    elif memo_type == StellarMemoType.HASH:
        description = "Memo (HASH)"
    elif memo_type == StellarMemoType.RETURN:
        description = "Memo (RETURN)"
    else:
        return await layouts.confirm_action(
            "confirm_memo",
            "Confirm memo",
            "No memo set!",
            "Important: Many exchanges require a memo when depositing",
            br_code=ButtonRequestType.ConfirmOutput,
        )

    await layouts.confirm_blob(
        "confirm_memo",
        "Confirm memo",
        memo_text,
        description,
    )


async def require_confirm_final(fee: int, num_operations: int) -> None:
    op_str = strings.format_plural("{count} {plural}", num_operations, "operation")
    await layouts.confirm_metadata(
        "confirm_final",
        "Final confirm",
        "Sign this transaction made up of " + op_str + " and pay {}\nfor fee?",
        format_amount(fee),
        hold=True,
    )


def format_asset(asset: StellarAsset | None) -> str:
    from trezor.enums import StellarAssetType
    from trezor.wire import DataError

    if asset is None or asset.type == StellarAssetType.NATIVE:
        return "XLM"
    else:
        if asset.code is None:
            raise DataError("Stellar asset code is missing")
        return asset.code


def format_amount(amount: int, asset: StellarAsset | None = None) -> str:
    return (
        strings.format_amount(amount, consts.AMOUNT_DECIMALS)
        + " "
        + format_asset(asset)
    )


async def require_confirm_sc_val(
    parent_objects: list[str],
    val: StellarSCVal,
) -> None:
    title = limit_str(".".join(parent_objects))

    async def confirm_sc_val(data_type: str, data: str) -> None:
        await layouts.confirm_properties(
            "confirm_sc_val",
            title,
            (("val type:", data_type), ("val:", data)),
        )

    if val.type == StellarSCValType.SCV_BOOL:
        await confirm_sc_val("bool", "true" if val.b else "false")
    elif val.type == StellarSCValType.SCV_VOID:
        await confirm_sc_val("void", "[no content]")
    elif val.type == StellarSCValType.SCV_ERROR:
        raise DataError(f"Stellar: Unsupported SCV type: {val.type}")
    elif val.type == StellarSCValType.SCV_U32:
        # TODO: format number
        await confirm_sc_val("uint32", str(val.u32))
    elif val.type == StellarSCValType.SCV_I32:
        await confirm_sc_val("int32", str(val.i32))
    elif val.type == StellarSCValType.SCV_U64:
        await confirm_sc_val("uint64", str(val.u64))
    elif val.type == StellarSCValType.SCV_I64:
        await confirm_sc_val("int64", str(val.i64))
    elif val.type == StellarSCValType.SCV_TIMEPOINT:
        await confirm_sc_val("timepoint", str(val.timepoint))
    elif val.type == StellarSCValType.SCV_DURATION:
        await confirm_sc_val("duration", str(val.duration))
    elif val.type == StellarSCValType.SCV_U128:
        assert val.u128
        value_bytes = helpers.int_to_bytes(val.u128.hi, 8) + helpers.int_to_bytes(
            val.u128.lo, 8
        )
        v = helpers.bytes_to_int(value_bytes)
        await confirm_sc_val("uint128", str(v))
    elif val.type == StellarSCValType.SCV_I128:
        assert val.i128
        value_bytes = helpers.int_to_bytes(val.i128.hi, 8, True) + helpers.int_to_bytes(
            val.i128.lo, 8
        )
        v = helpers.bytes_to_int(value_bytes, True)
        await confirm_sc_val("int128", str(v))
    elif val.type == StellarSCValType.SCV_U256:
        assert val.u256
        value_bytes = (
            helpers.int_to_bytes(val.u256.hi_hi, 8)
            + helpers.int_to_bytes(val.u256.hi_lo, 8)
            + helpers.int_to_bytes(val.u256.lo_hi, 8)
            + helpers.int_to_bytes(val.u256.lo_lo, 8)
        )
        v = helpers.bytes_to_int(value_bytes)
        await confirm_sc_val("uint256", str(v))
    elif val.type == StellarSCValType.SCV_I256:
        assert val.i256
        value_bytes = (
            helpers.int_to_bytes(val.i256.hi_hi, 8, True)
            + helpers.int_to_bytes(val.i256.hi_lo, 8)
            + helpers.int_to_bytes(val.i256.lo_hi, 8)
            + helpers.int_to_bytes(val.i256.lo_lo, 8)
        )
        v = helpers.bytes_to_int(value_bytes, True)
        await confirm_sc_val("int256", str(v))
    elif val.type == StellarSCValType.SCV_BYTES:
        assert val.bytes is not None
        await confirm_blob("confirm_sc_val", title, val.bytes, "val(bytes):")
    elif val.type == StellarSCValType.SCV_STRING:
        assert val.string is not None
        await confirm_sc_val("string", val.string)
    elif val.type == StellarSCValType.SCV_SYMBOL:
        assert val.symbol is not None
        await confirm_sc_val("symbol", val.symbol)
    elif val.type == StellarSCValType.SCV_VEC:
        if await should_show_more(
            title,
            ((ui.NORMAL, f"{title} contains {len(val.vec)} elements"),),
            "Show full vec",
            "should_show_vec",
        ):
            for idx, item in enumerate(val.vec):
                await require_confirm_sc_val(parent_objects + [str(idx)], item)
    elif val.type == StellarSCValType.SCV_MAP:
        if await should_show_more(
            title,
            ((ui.NORMAL, f"{title} contains {len(val.map)} items"),),
            "Show full map",
            "should_show_map",
        ):
            for idx, item in enumerate(val.map):
                assert item.key
                assert item.value
                await require_confirm_sc_val(
                    parent_objects + [str(idx), "key"], item.key
                )
                await require_confirm_sc_val(
                    parent_objects + [str(idx), "value"], item.value
                )
    elif val.type == StellarSCValType.SCV_ADDRESS:
        assert val.address
        await confirm_sc_val("address", val.address.address)
    elif val.type == StellarSCValType.SCV_CONTRACT_INSTANCE:
        assert val.instance
        props: list[tuple[str, str]] = [("val type:", "contract instance")]
        if (
            val.instance.executable.type
            == StellarContractExecutableType.CONTRACT_EXECUTABLE_WASM
        ):
            assert val.instance.executable
            assert val.instance.executable.wasm_hash
            props.append(("executable.type", "CONTRACT_EXECUTABLE_WASM"))
            props.append(
                (
                    "executable.wasm_hash",
                    ubinascii.hexlify(val.instance.executable.wasm_hash).decode(
                        "utf-8"
                    ),
                )
            )
            pass
        elif (
            val.instance.executable.type
            == StellarContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET
        ):
            props.append(("executable.type", "CONTRACT_EXECUTABLE_STELLAR_ASSET"))
            pass
        else:
            raise DataError(
                f"Stellar: Unsupported executable type: {val.instance.executable.type}"
            )

        await layouts.confirm_properties("confirm_sc_val", title, props)

        if await should_show_more(
            title,
            ((ui.NORMAL, f"{title} contains storage"),),
            "Show full storage",
            "should_show_storage",
        ):
            for idx, item in enumerate(val.instance.storage):
                assert item.key
                assert item.value
                await require_confirm_sc_val(
                    parent_objects + [str(idx), "storage", "key"], item.key
                )
                await require_confirm_sc_val(
                    parent_objects + [str(idx), "storage", "value"], item.value
                )
    elif val.type == StellarSCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE:
        await confirm_sc_val("ledger key contract instance", "[no content]")
    elif val.type == StellarSCValType.SCV_LEDGER_KEY_NONCE:
        await confirm_sc_val("ledger key nonce", str(val.nonce_key))
    else:
        raise DataError(f"Stellar: Unsupported SCV type: {val.type}")


async def confirm_soroban_authorized_function(
    parent_objects: list[str], func: StellarSorobanAuthorizedFunction
):
    if (
        func.type
        != StellarSorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN
    ):
        raise DataError(f"Stellar: unsupported function type: {func.type}")
    assert func.contract_fn

    title = limit_str(".".join(parent_objects)) or "root invocation"
    await layouts.confirm_properties(
        "confirm_soroban_auth",
        title,
        (
            (
                "Contract Address",
                func.contract_fn.contract_address.address,
            ),
            ("Function", func.contract_fn.function_name),
        ),
    )

    # confirm args
    for idx, arg in enumerate(func.contract_fn.args):
        await require_confirm_sc_val(parent_objects + ["args", str(idx)], arg)


async def require_confirm_soroban_authorized_invocation(
    parent_objects: list[str],
    invocation: StellarSorobanAuthorizedInvocation,
) -> None:
    # confirm contract function
    await confirm_soroban_authorized_function(parent_objects, invocation.function)

    title = limit_str(".".join(parent_objects)) or "root invocation"

    # confirm sub_invocations
    if len(invocation.sub_invocations) and await should_show_more(
        title,
        (
            (
                ui.NORMAL,
                f"{title} contains {len(invocation.sub_invocations)} sub invocations",
            ),
        ),
        "Show Sub Invocations",
        "should_show_sub_invocations",
    ):
        for idx, sub_invocation in enumerate(invocation.sub_invocations):
            await require_confirm_soroban_authorized_invocation(
                parent_objects + ["subs", str(idx)],
                sub_invocation,
            )


async def require_confirm_soroban_auth_info(
    nonce: int,
    signature_expiration_ledger: int,
    invocation: StellarSorobanAuthorizedInvocation,
) -> None:
    await layouts.confirm_properties(
        "confirm_soroban_auth_info",
        "Confirm Soroban Auth",
        (
            ("Nonce", str(nonce)),
            ("Signature Exp Ledger", str(signature_expiration_ledger)),
        ),
    )
    await require_confirm_soroban_authorized_invocation([], invocation)


async def confirm_soroban_auth_final() -> None:
    from trezor.ui.layouts import confirm_action

    await confirm_action(
        "confirm_soroban_auth_final",
        "Confirm Soroban Auth",
        "Really sign Soroban Auth?",
        verb="Hold to confirm",
        hold=True,
    )


def limit_str(s: str, limit: int = 16) -> str:
    """Shortens string to show the last <limit> characters."""
    if len(s) <= limit + 2:
        return s

    return ".." + s[-limit:]
