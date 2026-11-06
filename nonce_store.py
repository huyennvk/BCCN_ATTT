"""Replay protection and idempotency stores.

The in-memory implementation is deterministic and thread-safe inside one
process. RedisReplayStore uses one Lua script to reserve the nonce and business
MessageID atomically across processes. Select TTLs to match the actual payment
and dispute-retention policy before production use.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import threading
import time
from typing import Protocol


# Timestamp bounds are inclusive, so a future-boundary packet can remain valid for 2W.
TIMESTAMP_WINDOW_SECONDS = 300
NONCE_TTL_MARGIN_SECONDS = 60
NONCE_TTL_SECONDS = 2 * TIMESTAMP_WINDOW_SECONDS + NONCE_TTL_MARGIN_SECONDS
IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60


class ReplayStoreUnavailable(ConnectionError):
    """Raised when replay protection cannot be checked safely."""


class ReplayStore(Protocol):
    nonce_ttl: int

    def nonce_seen(self, merchant_id: str, nonce: str, now_epoch: float | None = None) -> bool: ...
    def consume(
        self,
        merchant_id: str,
        nonce: str,
        message_id: str,
        now_epoch: float | None = None,
    ) -> str | None: ...


class InMemoryReplayStore:
    """Thread-safe single-process store with lazy heap-based expiry pruning."""

    def __init__(
        self,
        nonce_ttl: int = NONCE_TTL_SECONDS,
        message_ttl: int = IDEMPOTENCY_TTL_SECONDS,
    ) -> None:
        if nonce_ttl <= 0 or message_ttl <= 0:
            raise ValueError("TTLs must be positive")
        self.nonce_ttl = nonce_ttl
        self.message_ttl = message_ttl
        self._nonces: dict[tuple[str, str], float] = {}
        self._messages: dict[tuple[str, str], float] = {}
        self._expiry_heap: list[tuple[float, str, tuple[str, str]]] = []
        self._lock = threading.Lock()
        self.down = False  # fault injection for tests only

    def _prune(self, now: float) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= now:
            expires, kind, key = heapq.heappop(self._expiry_heap)
            table = self._nonces if kind == "nonce" else self._messages
            if table.get(key) == expires:
                del table[key]

    def nonce_seen(self, merchant_id: str, nonce: str, now_epoch: float | None = None) -> bool:
        if self.down:
            raise ReplayStoreUnavailable("replay store unavailable")
        now = time.time() if now_epoch is None else float(now_epoch)
        key = (merchant_id, nonce)
        with self._lock:
            self._prune(now)
            return key in self._nonces

    def consume(
        self,
        merchant_id: str,
        nonce: str,
        message_id: str,
        now_epoch: float | None = None,
    ) -> str | None:
        """Atomically reserve nonce and idempotency key.

        Returns ``REPLAY_DETECTED`` or ``DUPLICATE_MESSAGE`` on collision,
        ``None`` on success.
        """
        if self.down:
            raise ReplayStoreUnavailable("replay store unavailable")
        now = time.time() if now_epoch is None else float(now_epoch)
        nonce_key = (merchant_id, nonce)
        message_key = (merchant_id, message_id)
        with self._lock:
            self._prune(now)
            if nonce_key in self._nonces:
                return "REPLAY_DETECTED"
            if message_key in self._messages:
                return "DUPLICATE_MESSAGE"
            nonce_expiry = now + self.nonce_ttl
            message_expiry = now + self.message_ttl
            self._nonces[nonce_key] = nonce_expiry
            self._messages[message_key] = message_expiry
            heapq.heappush(self._expiry_heap, (nonce_expiry, "nonce", nonce_key))
            heapq.heappush(self._expiry_heap, (message_expiry, "message", message_key))
            return None

    def clear(self) -> None:
        with self._lock:
            self._nonces.clear()
            self._messages.clear()
            self._expiry_heap.clear()

    def size(self) -> tuple[int, int]:
        with self._lock:
            return len(self._nonces), len(self._messages)


_REDIS_RESERVE_SCRIPT = """
local nonce_exists = redis.call('EXISTS', KEYS[1])
if nonce_exists == 1 then return 1 end
local message_exists = redis.call('EXISTS', KEYS[2])
if message_exists == 1 then return 2 end
redis.call('SET', KEYS[1], '1', 'EX', ARGV[1])
redis.call('SET', KEYS[2], '1', 'EX', ARGV[2])
return 0
"""


class RedisReplayStore:
    """Optional multi-process replay store backed by Redis.

    Install ``redis`` separately (``pip install redis``). Network failures raise
    ReplayStoreUnavailable; callers must fail closed rather than bypass replay
    checks.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        nonce_ttl: int = NONCE_TTL_SECONDS,
        message_ttl: int = IDEMPOTENCY_TTL_SECONDS,
        key_prefix: str = "bccn-attt",
    ) -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("Install redis to use RedisReplayStore: pip install redis") from exc
        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self.nonce_ttl = nonce_ttl
        self.message_ttl = message_ttl
        self.key_prefix = key_prefix
        self.down = False  # fault injection for tests only

    def _key(self, kind: str, merchant_id: str, value: str) -> str:
        raw = json.dumps([merchant_id, value], ensure_ascii=False, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        return "%s:%s:%s" % (self.key_prefix, kind, digest)

    def nonce_seen(self, merchant_id: str, nonce: str, now_epoch: float | None = None) -> bool:
        if self.down:
            raise ReplayStoreUnavailable("replay store unavailable")
        try:
            return bool(self._redis.exists(self._key("nonce", merchant_id, nonce)))
        except Exception as exc:  # Redis exception types vary by redis-py release
            raise ReplayStoreUnavailable("replay store unavailable") from exc

    def consume(
        self,
        merchant_id: str,
        nonce: str,
        message_id: str,
        now_epoch: float | None = None,
    ) -> str | None:
        if self.down:
            raise ReplayStoreUnavailable("replay store unavailable")
        nonce_key = self._key("nonce", merchant_id, nonce)
        message_key = self._key("message", merchant_id, message_id)
        try:
            result = int(
                self._redis.eval(
                    _REDIS_RESERVE_SCRIPT,
                    2,
                    nonce_key,
                    message_key,
                    self.nonce_ttl,
                    self.message_ttl,
                )
            )
        except Exception as exc:  # Redis exception types vary by redis-py release
            raise ReplayStoreUnavailable("replay store unavailable") from exc
        if result == 1:
            return "REPLAY_DETECTED"
        if result == 2:
            return "DUPLICATE_MESSAGE"
        return None
