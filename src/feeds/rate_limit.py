import time
from dataclasses import dataclass, field

import httpx

from config import settings


@dataclass
class RateLimitState:
    last_request_at: float = 0.0
    retry_after: float = 0.0


_states: dict[str, RateLimitState] = {}


def _state(source: str) -> RateLimitState:
    if source not in _states:
        _states[source] = RateLimitState()
    return _states[source]


def nvd_interval_seconds() -> float:
    return 0.6 if settings.nvd_api_key else 6.5


def wait_for_slot(source: str, interval_seconds: float) -> None:
    state = _state(source)
    now = time.monotonic()
    if state.retry_after > now:
        time.sleep(state.retry_after - now)
        now = time.monotonic()
    elapsed = now - state.last_request_at
    if elapsed < interval_seconds:
        time.sleep(interval_seconds - elapsed)
    state.last_request_at = time.monotonic()


def mark_rate_limited(source: str, retry_after_seconds: float) -> None:
    state = _state(source)
    state.retry_after = time.monotonic() + retry_after_seconds


def seconds_until_retry(source: str) -> int:
    state = _state(source)
    remaining = state.retry_after - time.monotonic()
    return max(0, int(remaining))


def request_with_backoff(
    source: str,
    interval_seconds: float,
    request_fn,
    *,
    max_retries: int = 3,
) -> httpx.Response:
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        wait_for_slot(source, interval_seconds)
        try:
            response = request_fn()
            if response.status_code in (403, 429):
                retry_after = float(response.headers.get("Retry-After", interval_seconds * (attempt + 2)))
                mark_rate_limited(source, retry_after)
                last_exc = httpx.HTTPStatusError(
                    f"Rate limited ({response.status_code})",
                    request=response.request,
                    response=response,
                )
                continue
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 429):
                retry_after = float(exc.response.headers.get("Retry-After", interval_seconds * (attempt + 2)))
                mark_rate_limited(source, retry_after)
                last_exc = exc
                continue
            raise
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(interval_seconds * (attempt + 1))
    if last_exc:
        raise last_exc
    raise RuntimeError("request_with_backoff failed without exception")