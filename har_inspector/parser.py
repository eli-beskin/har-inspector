"""Load a HAR file and map raw entries to model.Entry."""

import json
from datetime import datetime

from har_inspector.model import Entry, HarFile, Timings


class HarError(Exception):
    """The input is not a usable HAR file."""


def load(path: str) -> HarFile:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise HarError(f"file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise HarError(f"cannot read {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise HarError(f"not valid JSON: {path} ({exc})") from None

    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise HarError(f"not a HAR file (missing log.entries): {path}")

    creator = log.get("creator") or {}
    creator_str = " ".join(
        str(part) for part in (creator.get("name"), creator.get("version")) if part
    )
    entries = []
    for i, raw in enumerate(log["entries"]):
        try:
            entries.append(_entry(i, raw))
        except (KeyError, TypeError, ValueError) as exc:
            raise HarError(f"entry #{i} is malformed: {exc!r}") from None
    return HarFile(path, creator_str, len(log.get("pages") or []), entries)


def _entry(index: int, raw: dict) -> Entry:
    request = raw["request"]
    response = raw["response"]
    return Entry(
        index=index,
        started=datetime.fromisoformat(raw["startedDateTime"]),
        time_ms=max(float(raw.get("time") or 0), 0.0),
        method=request.get("method", "?"),
        url=request.get("url", ""),
        status=int(response.get("status") or 0),
        status_text=response.get("statusText") or "",
        server_ip=raw.get("serverIPAddress") or "",
        transfer_size=_transfer_size(response),
        error=response.get("_error") or None,
        resource_type=raw.get("_resourceType"),
        response_headers=[
            (h.get("name", ""), h.get("value", "")) for h in response.get("headers") or []
        ],
        timings=_timings(raw.get("timings") or {}),
    )


def _timings(raw: dict) -> Timings:
    # Any negative value means "not applicable": Chrome writes -1, but also
    # small negatives like -0.8 from clock rounding (seen in real exports).
    def phase(name):
        value = raw.get(name)
        if not isinstance(value, (int, float)) or value < 0:
            return None
        return float(value)

    return Timings(**{name: phase(name) for name in Timings.__dataclass_fields__})


def _transfer_size(response: dict) -> int | None:
    # Chrome's _transferSize is the real on-the-wire size. Chrome sets
    # headersSize/bodySize to -1, so the fallback only helps other browsers.
    size = response.get("_transferSize")
    if isinstance(size, (int, float)) and size >= 0:
        return int(size)
    headers, body = response.get("headersSize"), response.get("bodySize")
    if isinstance(headers, (int, float)) and isinstance(body, (int, float)):
        if headers >= 0 and body >= 0:
            return int(headers + body)
    return None
