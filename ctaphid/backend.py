"""What an authenticator *is*, separated from how it is spoken to.

This module is the seam the milestone brief asks for. Above it: CTAPHID
framing, channels, the device node -- all Linux-specific. Below it: CTAP2
semantics, which are not. A Kotlin implementation on Android would implement
:class:`AuthenticatorBackend` and ``get_info``/``handle_cbor`` against a
``FileDescriptor``, and none of the transport code would need to change.

Only ``authenticatorGetInfo`` is implemented. Every other CTAP2 command is
answered with ``CTAP2_ERR_INVALID_COMMAND``, which is the honest response and
the one the specification prescribes for a command an authenticator does not
support.
"""

from __future__ import annotations

import abc
import logging

from . import cbor
from .constants import Ctap2Command, Ctap2Error, max_message_size

log = logging.getLogger("ctaphid.backend")

#: Development AAGUID.
#
# An AAGUID is a 16-byte identifier that tells a relying party which
# authenticator model it is talking to; real ones are registered with the FIDO
# Alliance and are how a relying party decides whether to trust a device. This
# value is deliberately *not* a registered one, and deliberately spells out
# what it is in ASCII so that no one can mistake it for a claimed identity.
#
# Replacing it is a prerequisite for anything beyond this milestone: a relying
# party will not recognise this AAGUID, and it must not be presented as a
# certified or commercial device.
DEVELOPMENT_AAGUID = b"PocoF7-CTAP2-DEV"
assert len(DEVELOPMENT_AAGUID) == 16, "an AAGUID is exactly 16 bytes"

#: CTAP versions this authenticator claims. Only 2.0 -- the response format
#: below is the 2.0 set of fields, and claiming 2.1 would oblige us to return
#: fields (pinUvAuthProtocols, and so on) that do not exist yet.
VERSIONS = ["FIDO_2_0"]

#: Transport hints, reported so a client can tell how it reached us.
TRANSPORTS = ["usb"]

#: Options, reported honestly.
#
# The specification says an option that is absent is unsupported, but several
# clients read the value rather than the presence, so every option this
# authenticator could plausibly be asked about is listed explicitly as False.
# None of these are implemented in this milestone:
#
#   rk         no resident (discoverable) credential storage
#   up         no user-presence mechanism -- there is no button or touch sensor
#   uv         no built-in user verification
#   clientPin  no PIN support
#
# ``up: False`` in particular is unusual for a shipping authenticator, and it
# is the correct answer: this milestone implements no command that requires
# user presence, and claiming otherwise would invite a relying party to rely on
# a gesture that cannot happen. It is also why ``plat`` is omitted -- that
# option is for platform authenticators, and this is a roaming one.
OPTIONS: dict[str, bool] = {
    "rk": False,
    "up": False,
    "uv": False,
    "clientPin": False,
}

#: GetInfo response map keys, from CTAP 2.1 section 6.4.
_KEY_VERSIONS = 0x01
_KEY_AAGUID = 0x03
_KEY_OPTIONS = 0x04
_KEY_MAX_MSG_SIZE = 0x05
_KEY_TRANSPORTS = 0x09


class AuthenticatorBackend(abc.ABC):
    """The authenticator itself, independent of transport.

    Implementations receive a complete reassembled CTAP2 request and return a
    complete CTAP2 response. They never see packets, channels or file
    descriptors.
    """

    @property
    @abc.abstractmethod
    def aaguid(self) -> bytes:
        """16-byte authenticator identifier."""

    @property
    @abc.abstractmethod
    def max_msg_size(self) -> int:
        """Largest CTAP2 message this authenticator will accept."""

    @abc.abstractmethod
    def get_info(self) -> dict:
        """Build the authenticatorGetInfo response as a CBOR-ready map."""

    @abc.abstractmethod
    def handle_cbor(self, request: bytes) -> bytes:
        """Dispatch one CTAP2 request and return the response body.

        The returned bytes are what goes inside a CTAPHID_CBOR message. Every
        response -- success or failure -- begins with a CTAP2 status byte; on
        success ``CTAP2_OK`` (0x00) is followed by the CBOR payload, and on
        failure the status byte stands alone.
        """


class GetInfoBackend(AuthenticatorBackend):
    """An authenticator that can describe itself and nothing else.

    This is the whole of Milestone 2's CTAP2 surface. Deliberately named for
    what it does rather than for what it is, so that adding a real credential
    store means adding a sibling class rather than growing this one.
    """

    def __init__(self, packet_size: int = 64, aaguid: bytes = DEVELOPMENT_AAGUID):
        if len(aaguid) != 16:
            raise ValueError(f"aaguid must be 16 bytes, got {len(aaguid)}")
        self._aaguid = aaguid
        self._packet_size = packet_size

    @property
    def aaguid(self) -> bytes:
        return self._aaguid

    @property
    def max_msg_size(self) -> int:
        # Bounded by what the transport can reassemble, not by what this
        # backend would prefer: advertising more than the framing layer can
        # deliver would let a client send a request that gets truncated.
        return max_message_size(self._packet_size)

    def get_info(self) -> dict:
        return {
            _KEY_VERSIONS: list(VERSIONS),
            _KEY_AAGUID: self._aaguid,
            _KEY_OPTIONS: dict(OPTIONS),
            _KEY_MAX_MSG_SIZE: self.max_msg_size,
            _KEY_TRANSPORTS: list(TRANSPORTS),
        }

    def handle_cbor(self, request: bytes) -> bytes:
        """Dispatch a CTAP2 request.

        A request is ``command_byte || cbor_parameters``; a response is
        ``status_byte || cbor``, with the status byte standing alone on
        failure. Only GetInfo is accepted; everything else returns
        ``CTAP2_ERR_INVALID_COMMAND``.
        """
        if not request:
            log.info("CBOR request with no command byte")
            return bytes([Ctap2Error.INVALID_LENGTH])

        command = request[0]
        params = request[1:]

        # Validate the parameter block before dispatching, so that a malformed
        # message is reported as malformed rather than as an unknown command.
        # GetInfo takes no parameters, and a conforming client sends none, but
        # some send an empty map, so an empty parameter block and a decodable
        # one are both accepted.
        if params:
            try:
                cbor.decode(params)
            except cbor.CborError as exc:
                log.info("CBOR command 0x%02x had undecodable parameters: %s", command, exc)
                return bytes([Ctap2Error.INVALID_CBOR])

        try:
            parsed = Ctap2Command(command)
        except ValueError:
            log.info("unsupported CTAP2 command 0x%02x (%d parameter bytes)",
                     command, len(params))
            return bytes([Ctap2Error.INVALID_COMMAND])

        if parsed is not Ctap2Command.GET_INFO:
            log.info("CTAP2 command %s is not implemented in this milestone", parsed.name)
            return bytes([Ctap2Error.INVALID_COMMAND])

        # CTAP2_OK is not implicit: the status byte leads every response, and a
        # client reads byte 0 as the status before decoding anything. Omitting
        # it makes the CBOR map's own first byte (0xa5 for a five-entry map) be
        # read as an error code.
        body = cbor.encode(self.get_info())
        response = bytes([Ctap2Error.SUCCESS]) + body
        log.info("GetInfo -> status 0x00, %d bytes of CBOR", len(body))
        # Truncated at DEBUG: the response is public, but there is no reason to
        # put a full protocol dump in a default log.
        log.debug("GetInfo response: %s", response.hex())
        return response


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> None:
    backend = GetInfoBackend(packet_size=64)
    assert backend.max_msg_size == 7609

    # GetInfo round-trips through our own CBOR codec and has the right shape.
    response = backend.handle_cbor(b"\x04")
    assert response[0] == Ctap2Error.SUCCESS, (
        "a success response must lead with CTAP2_OK, or the client reads the "
        "CBOR map header as an error code"
    )
    info = cbor.decode(response[1:])
    assert info[_KEY_VERSIONS] == ["FIDO_2_0"]
    assert info[_KEY_AAGUID] == DEVELOPMENT_AAGUID
    assert len(info[_KEY_AAGUID]) == 16
    assert info[_KEY_MAX_MSG_SIZE] == 7609
    assert info[_KEY_TRANSPORTS] == ["usb"]

    # Nothing unsupported may be advertised.
    for option in ("rk", "up", "uv", "clientPin"):
        assert info[_KEY_OPTIONS][option] is False, f"{option} advertised as supported"
    assert 0x06 not in info, "pinUvAuthProtocols must not be sent when claiming FIDO_2_0"
    assert 0x0A not in info, "algorithms must not be advertised without makeCredential"

    # GetInfo tolerates an empty CBOR parameter map, which some clients send.
    assert backend.handle_cbor(b"\x04\xa0") == response

    # Every other command is refused, and refused with the right status byte.
    for command in (0x01, 0x02, 0x06, 0x07, 0x08, 0x0A, 0x0D):
        assert backend.handle_cbor(bytes([command])) == bytes([Ctap2Error.INVALID_COMMAND]), (
            f"command 0x{command:02x} was not refused"
        )

    # An unknown command byte is refused too, not treated as GetInfo.
    assert backend.handle_cbor(b"\xff") == bytes([Ctap2Error.INVALID_COMMAND])

    # Malformed parameters are reported as malformed.
    assert backend.handle_cbor(b"\x04\xff") == bytes([Ctap2Error.INVALID_CBOR])
    assert backend.handle_cbor(b"\x04\x1f") == bytes([Ctap2Error.INVALID_CBOR])

    # An empty request is a length error, not a crash.
    assert backend.handle_cbor(b"") == bytes([Ctap2Error.INVALID_LENGTH])

    # A non-16-byte AAGUID is rejected at construction rather than on the wire.
    try:
        GetInfoBackend(aaguid=b"too short")
    except ValueError:
        pass
    else:
        raise AssertionError("a short AAGUID was accepted")

    print("backend selftest OK")


if __name__ == "__main__":
    _selftest()
