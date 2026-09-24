"""A minimal CTAPHID authenticator, spoken over a Linux USB HID gadget.

The package is split so that the transport can be lifted out and re-hosted
later, which is what the milestone brief asks for:

    constants.py  protocol numbers, no logic
    framing.py    packet <-> message, pure functions over bytes
    channels.py   channel allocation and INIT/resynchronisation rules
    cbor.py       the subset of CBOR that CTAP2 GetInfo needs
    backend.py    what an authenticator *is* -- the seam a Kotlin
                  implementation would sit behind
    transport.py  the only module that touches /dev/hidgN or configfs
    server.py     the main loop that ties the above together

Nothing in the first five imports anything platform-specific, and only
``transport.py`` opens a device. That is deliberate.
"""

__all__ = [
    "backend",
    "cbor",
    "channels",
    "constants",
    "framing",
    "server",
    "transport",
]
