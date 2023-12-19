from micropython import const
from typing import TYPE_CHECKING

from trezor.enums import MessageType

if TYPE_CHECKING:
    from trezor import protobuf
    from trezor.messages import (
        StellarAccountMergeOp,
        StellarAllowTrustOp,
        StellarBumpSequenceOp,
        StellarChangeTrustOp,
        StellarClaimClaimableBalanceOp,
        StellarCreateAccountOp,
        StellarCreatePassiveSellOfferOp,
        StellarManageBuyOfferOp,
        StellarManageDataOp,
        StellarManageSellOfferOp,
        StellarPathPaymentStrictReceiveOp,
        StellarPathPaymentStrictSendOp,
        StellarPaymentOp,
        StellarSetOptionsOp,
    )

    StellarMessageType = (
        StellarAccountMergeOp
        | StellarAllowTrustOp
        | StellarBumpSequenceOp
        | StellarChangeTrustOp
        | StellarCreateAccountOp
        | StellarCreatePassiveSellOfferOp
        | StellarManageDataOp
        | StellarManageBuyOfferOp
        | StellarManageSellOfferOp
        | StellarPathPaymentStrictReceiveOp
        | StellarPathPaymentStrictSendOp
        | StellarPaymentOp
        | StellarSetOptionsOp
        | StellarClaimClaimableBalanceOp
    )


TX_TYPE = b"\x00\x00\x00\x02"

# source: https://github.com/stellar/go/blob/a1db2a6b1f/xdr/Stellar-transaction.x#L35
# Inflation not supported see https://github.com/trezor/trezor-core/issues/202#issuecomment-393342089
op_codes: dict[int, int] = {
    MessageType.StellarAccountMergeOp: 8,
    MessageType.StellarAllowTrustOp: 7,
    MessageType.StellarBumpSequenceOp: 11,
    MessageType.StellarChangeTrustOp: 6,
    MessageType.StellarCreateAccountOp: 0,
    MessageType.StellarCreatePassiveSellOfferOp: 4,
    MessageType.StellarManageDataOp: 10,
    MessageType.StellarManageBuyOfferOp: 12,
    MessageType.StellarManageSellOfferOp: 3,
    MessageType.StellarPathPaymentStrictReceiveOp: 2,
    MessageType.StellarPathPaymentStrictSendOp: 13,
    MessageType.StellarPaymentOp: 1,
    MessageType.StellarSetOptionsOp: 5,
    MessageType.StellarClaimClaimableBalanceOp: 15,
}

# StellarSCValType
SCV_BOOL = 0
SCV_VOID = 1
SCV_ERROR = 2
SCV_U32 = 3
SCV_I32 = 4
SCV_U64 = 5
SCV_I64 = 6
SCV_TIMEPOINT = 7
SCV_DURATION = 8
SCV_U128 = 9
SCV_I128 = 10
SCV_U256 = 11
SCV_I256 = 12
SCV_BYTES = 13
SCV_STRING = 14
SCV_SYMBOL = 15
SCV_VEC = 16
SCV_MAP = 17
SCV_ADDRESS = 18
SCV_CONTRACT_INSTANCE = 19
SCV_LEDGER_KEY_CONTRACT_INSTANCE = 20
SCV_LEDGER_KEY_NONCE = 21

# StellarSorobanAuthorizedFunctionType
SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN = 0

# StellarContractExecutableType
CONTRACT_EXECUTABLE_WASM = 0
CONTRACT_EXECUTABLE_STELLAR_ASSET = 1

# https://www.stellar.org/developers/guides/concepts/accounts.html#balance
# https://github.com/stellar/go/blob/3d2c1defe73dbfed00146ebe0e8d7e07ce4bb1b6/amount/main.go#L23
AMOUNT_DECIMALS = const(7)

# https://github.com/stellar/go/blob/master/network/main.go
NETWORK_PASSPHRASE_PUBLIC = "Public Global Stellar Network ; September 2015"
NETWORK_PASSPHRASE_TESTNET = "Test SDF Network ; September 2015"

# https://www.stellar.org/developers/guides/concepts/accounts.html#flags
FLAG_AUTH_REQUIRED = const(1)
FLAG_AUTH_REVOCABLE = const(2)
FLAG_AUTH_IMMUTABLE = const(4)
FLAGS_MAX_SIZE = const(7)


def get_op_code(msg: protobuf.MessageType) -> int:
    wire = msg.MESSAGE_WIRE_TYPE
    if wire not in op_codes:
        raise ValueError("Stellar: op code unknown")
    assert isinstance(wire, int)
    return op_codes[wire]
