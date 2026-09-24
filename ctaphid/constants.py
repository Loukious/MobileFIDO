"""CTAPHID protocol constants.

Reference: FIDO Client to Authenticator Protocol (CTAP) 2.1, section 11.2
("USB HID"), plus the U2F HID protocol that the framing originates from.

Every value here was cross-checked against Yubico's python-fido2
(``fido2/hid/__init__.py``), because that library is the client this milestone
is tested with. If the two ever disagree, the test fails for reasons that have
nothing to do with the gadget, so python-fido2 is treated as the tie-breaker.

Nothing in this module touches a device. Importing it is inert.
"""

from enum import IntEnum

# ---------------------------------------------------------------------------
# Packet framing
# ---------------------------------------------------------------------------

#: Set in the command byte of an initialization packet. A continuation packet
#: always has this bit clear, which is how the two are told apart on the wire.
TYPE_INIT = 0x80

#: The channel used to request a new channel. ``0x00000000`` is reserved, and
#: ``0xFFFFFFFF`` is broadcast.
CID_BROADCAST = 0xFFFFFFFF
CID_RESERVED = 0x00000000

#: Bytes of channel ID at the start of every packet.
CID_LENGTH = 4

#: Initialization packet header: CID(4) + CMD(1) + BCNTH(1) + BCNTL(1).
INIT_HEADER_LENGTH = 7

#: Continuation packet header: CID(4) + SEQ(1).
CONT_HEADER_LENGTH = 5

#: Sequence numbers run 0x00..0x7f; bit 7 is always clear.
MAX_SEQ = 0x7F


class CtapHidCommand(IntEnum):
    """CTAPHID command bytes.

    The specification lists these by name; the numeric values are the ones
    python-fido2 uses, which in turn match every shipping authenticator.
    """

    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F

    #: Commands at or above this are vendor-defined.
    VENDOR_FIRST = 0x40


class CtapHidError(IntEnum):
    """CTAPHID error codes, carried in the single data byte of CTAPHID_ERROR."""

    INVALID_CMD = 0x01
    INVALID_PAR = 0x02
    INVALID_LEN = 0x03
    INVALID_SEQ = 0x04
    MSG_TIMEOUT = 0x05
    CHANNEL_BUSY = 0x06
    LOCK_REQUIRED = 0x0A
    INVALID_CHANNEL = 0x0B
    OTHER = 0x7F


class Capability(IntEnum):
    """Bits of the capabilities byte returned by CTAPHID_INIT.

    Only CBOR is advertised by this implementation -- see
    :data:`SUPPORTED_CAPABILITIES`.
    """

    WINK = 0x01
    #: Defined in the spec but explicitly marked "not used".
    LOCK = 0x02
    CBOR = 0x04
    NMSG = 0x08


#: Capabilities we actually implement.
#
# Deliberately only CBOR: this milestone handles CTAPHID_CBOR (GetInfo) and
# nothing else. WINK is absent because there is no indicator to blink, LOCK is
# absent because we do not implement CTAPHID_LOCK, and NMSG is absent because
# we do not accept CTAPHID_MSG. Advertising a capability we do not honour would
# make a client send us a command we then have to reject.
SUPPORTED_CAPABILITIES = Capability.CBOR

# ---------------------------------------------------------------------------
# Protocol / device version reported by CTAPHID_INIT
# ---------------------------------------------------------------------------

#: CTAPHID protocol version. 2 is the current revision and what every shipping
#: authenticator reports; python-fido2 stores this verbatim as
#: ``CtapHidDevice.version``.
CTAPHID_PROTOCOL_VERSION = 2

#: Device version, reported as three bytes. These identify *our* firmware, not
#: any FIDO certification. 0.1.0 = Milestone 2, transport only.
DEVICE_VERSION = (0, 1, 0)

# ---------------------------------------------------------------------------
# CTAP2 layer
# ---------------------------------------------------------------------------

#: CTAP2 commands. GetInfoBackend serves GetInfo alone; DevCredentialBackend
#: additionally serves makeCredential and getAssertion in development mode.
class Ctap2Command(IntEnum):
    MAKE_CREDENTIAL = 0x01
    GET_ASSERTION = 0x02
    GET_INFO = 0x04
    CLIENT_PIN = 0x06
    RESET = 0x07
    GET_NEXT_ASSERTION = 0x08
    BIO_ENROLLMENT = 0x09
    CREDENTIAL_MANAGEMENT = 0x0A
    SELECTION = 0x0B
    LARGE_BLOBS = 0x0C
    CONFIG = 0x0D


class Ctap2Error(IntEnum):
    """CTAP2 status bytes. Returned as a bare byte when the request itself
    could not be dispatched, and inside the response map otherwise."""

    SUCCESS = 0x00
    INVALID_COMMAND = 0x01
    INVALID_PARAMETER = 0x02
    INVALID_LENGTH = 0x03
    INVALID_SEQ = 0x04
    TIMEOUT = 0x05
    CHANNEL_BUSY = 0x06
    LOCK_REQUIRED = 0x0A
    INVALID_CHANNEL = 0x0B
    CBOR_UNEXPECTED_TYPE = 0x11
    INVALID_CBOR = 0x12
    MISSING_PARAMETER = 0x14
    LIMIT_EXCEEDED = 0x15
    UNSUPPORTED_EXTENSION = 0x16
    CREDENTIAL_EXCLUDED = 0x19
    UNSUPPORTED_ALGORITHM = 0x26
    OPERATION_DENIED = 0x27
    KEY_STORE_FULL = 0x28
    UNSUPPORTED_OPTION = 0x2B
    INVALID_OPTION = 0x2C
    KEEPALIVE_CANCEL = 0x2D
    NO_CREDENTIALS = 0x2E
    USER_ACTION_TIMEOUT = 0x2F
    NOT_ALLOWED = 0x30
    OTHER = 0x7F


# ---------------------------------------------------------------------------
# Message size
# ---------------------------------------------------------------------------

def max_message_size(packet_size: int) -> int:
    """Largest CTAPHID message that fits in ``packet_size``-byte packets.

    One initialization packet carries ``packet_size - 7`` bytes and up to 128
    continuation packets carry ``packet_size - 5`` bytes each. For the 64-byte
    packets this gadget uses that is 57 + 128*59 = 7609, which is the figure
    the U2F HID specification states.
    """
    return (packet_size - INIT_HEADER_LENGTH) + 128 * (packet_size - CONT_HEADER_LENGTH)


#: Human-readable names, used only for logging.
COMMAND_NAMES = {c.value: c.name for c in CtapHidCommand}
ERROR_NAMES = {e.value: e.name for e in CtapHidError}
