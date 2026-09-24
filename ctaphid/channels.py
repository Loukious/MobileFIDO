"""Channel bookkeeping and the INIT rules.

A "channel" is a logical conversation between host and authenticator. The host
picks one up by sending CTAPHID_INIT on the broadcast channel, and every
subsequent packet carries the channel ID it was given. Several channels can be
live at once, and packets for different channels interleave freely on the wire
-- which is the whole reason the channel ID is in the header.

Three rules matter here, and all three are easy to get subtly wrong:

1. **INIT on broadcast allocates.** The reply goes out on the *new* channel ID,
   not on broadcast, and it echoes the host's nonce verbatim.
2. **INIT on a channel that already exists is a resynchronisation, not an
   allocation.** This is what a host sends when it has lost track of a
   transaction -- after a timeout, or after its own state was reset. The reply
   must come back on the same channel and must report that same channel ID as
   the new one. Allocating a fresh ID here would strand the host, which is
   still addressing the old one.
3. **INIT on a channel that was never allocated is an error**, not an implicit
   allocation. The host may only obtain a channel through broadcast.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .constants import CID_BROADCAST, CID_RESERVED

#: How many channels may be live at once. Real authenticators support a
#: handful; browsers and python-fido2 use exactly one, so this is only ever
#: reached by a misbehaving or probing host.
MAX_CHANNELS = 8

#: Idle channels are reclaimed after this many seconds of silence.
#
# There is no CTAPHID command that releases a channel: a host simply stops
# using one, and Windows opens a fresh channel every time it enumerates the
# device. Measured on real hardware, that adds up fast -- a handful of
# disconnect/reconnect cycles fills the table with channels nobody will ever
# use again, and the next legitimate INIT gets ERR_CHANNEL_BUSY.
#
# So this is not merely a deadlock guard, it is the normal reclamation path,
# and the value is chosen to be useful rather than merely safe. Thirty seconds
# exceeds the partial-message timeout (5s); execution and partial messages
# are explicitly pinned, so long physical confirmation waits cannot lose their
# channels. The specification gives no number; it only says an authenticator
# may destroy a channel after a period of inactivity.
IDLE_TIMEOUT_SECONDS = 30.0


@dataclass
class Channel:
    """One allocated channel."""

    cid: int
    created: float
    last_used: float
    pinned: bool = False

    def touch(self, now: float) -> None:
        self.last_used = now


@dataclass
class ChannelTable:
    """The set of live channels."""

    max_channels: int = MAX_CHANNELS
    idle_timeout: float = IDLE_TIMEOUT_SECONDS
    channels: dict[int, Channel] = field(default_factory=dict)

    # -- queries ------------------------------------------------------------

    def __contains__(self, cid: int) -> bool:
        return cid in self.channels

    def __len__(self) -> int:
        return len(self.channels)

    def get(self, cid: int) -> Channel | None:
        return self.channels.get(cid)

    def touch(self, cid: int, now: float) -> None:
        channel = self.channels.get(cid)
        if channel is not None:
            channel.touch(now)

    def pin(self, cid: int) -> None:
        """Protect a channel while a request is being received or processed."""
        channel = self.channels.get(cid)
        if channel is not None:
            channel.pinned = True

    def unpin(self, cid: int) -> None:
        channel = self.channels.get(cid)
        if channel is not None:
            channel.pinned = False

    # -- mutation -----------------------------------------------------------

    def allocate(self, now: float) -> int | None:
        """Hand out a fresh channel ID, or ``None`` if the table is full.

        The ID is drawn at random rather than counted up. Sequential IDs would
        let a host guess another channel's ID, and channels are the only thing
        separating two concurrent conversations on the same wire.
        """
        if len(self.channels) >= self.max_channels:
            return None

        # 0x00000000 and 0xFFFFFFFF are reserved, and a collision would alias
        # two conversations onto one channel.
        for _ in range(64):
            candidate = int.from_bytes(os.urandom(4), "big")
            if candidate in (CID_RESERVED, CID_BROADCAST):
                continue
            if candidate in self.channels:
                continue
            self.channels[candidate] = Channel(candidate, now, now)
            return candidate

        return None

    def evict_lru(self) -> int | None:
        """Drop and return the least-recently-used channel, if any.

        Pinned channels have an incomplete message or an active backend call.
        An old timestamp alone is not evidence that such a channel is idle.
        """
        candidates = [channel for channel in self.channels.values() if not channel.pinned]
        if not candidates:
            return None
        victim = min(candidates, key=lambda channel: channel.last_used)
        del self.channels[victim.cid]
        return victim.cid

    def clear(self) -> int:
        """Drop every channel. Returns how many were dropped.

        The specification requires an authenticator to invalidate its channels
        when it detects a USB reset, because the host's view of the connection
        is gone at that point. A conforming host re-INITs, and python-fido2
        does exactly that whenever it constructs a new ``CtapHidDevice``.
        """
        count = len(self.channels)
        self.channels.clear()
        return count

    def expire(self, now: float) -> list[int]:
        """Reclaim channels idle for longer than ``idle_timeout``."""
        if self.idle_timeout <= 0:
            return []
        stale = [
            cid
            for cid, channel in self.channels.items()
            if not channel.pinned and now - channel.last_used > self.idle_timeout
        ]
        for cid in stale:
            del self.channels[cid]
        return stale


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> None:
    # Pin the timeout rather than inheriting the default: the arithmetic below
    # is about expiry behaviour, and must not silently change meaning if the
    # tuned production value is ever adjusted.
    table = ChannelTable(max_channels=3, idle_timeout=300.0)

    first = table.allocate(0.0)
    assert first is not None
    assert first not in (CID_RESERVED, CID_BROADCAST)
    assert first in table

    # IDs are not handed out twice.
    second = table.allocate(0.0)
    assert second is not None and second != first

    table.allocate(0.0)
    assert table.allocate(0.0) is None, "table should be full at max_channels"

    # Expiry frees the slots again, but only once they are genuinely idle.
    assert table.expire(1.0) == []
    table.touch(second, 100.0)
    expired = table.expire(400.0)
    assert second not in expired, "a recently touched channel was reclaimed"
    assert len(expired) == 2
    assert second in table

    # Clearing removes everything.
    assert table.clear() == 1
    assert len(table) == 0

    # Eviction reclaims the least-recently-used channel, and must never pick
    # the one that was just used -- that is the whole safety argument for
    # evicting instead of answering ERR_CHANNEL_BUSY.
    ev = ChannelTable(max_channels=2)
    a = ev.allocate(0.0)
    b = ev.allocate(0.0)
    assert a is not None and b is not None and a != b
    ev.touch(a, 50.0)  # a is the more recently used of the two
    assert ev.evict_lru() == b, "evicted a channel that was in recent use"
    assert a in ev and b not in ev
    assert ev.evict_lru() == a

    # Evicting an empty table is a no-op rather than an error, so the caller
    # can fall back to ERR_CHANNEL_BUSY without a special case.
    assert ev.evict_lru() is None
    assert len(ev) == 0

    # Random allocation over many draws stays inside the legal range and never
    # aliases an existing channel.
    big = ChannelTable(max_channels=64)
    seen = set()
    for _ in range(64):
        cid = big.allocate(0.0)
        assert cid is not None
        assert cid != CID_RESERVED and cid != CID_BROADCAST
        assert cid not in seen, "duplicate channel ID handed out"
        seen.add(cid)

    # An idle timeout of zero disables reclamation entirely.
    assert ChannelTable(idle_timeout=0.0).expire(1e9) == []

    # The production default must stay short enough to matter: a host that
    # re-enumerates leaves channels behind, and they have to age out quickly
    # or the next INIT is refused.
    assert IDLE_TIMEOUT_SECONDS <= 60.0, (
        f"idle timeout {IDLE_TIMEOUT_SECONDS}s is too long to reclaim "
        "channels abandoned by a re-enumerating host"
    )

    print("channels selftest OK")


if __name__ == "__main__":
    _selftest()
