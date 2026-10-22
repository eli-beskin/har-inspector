"""Text summary of a redaction run. Shows names and counts, never values."""

from collections import Counter

from har_inspector.redact.scrub import MIN_GLOBAL_LENGTH, Stats


def render(stats: Stats, source: str, target: str) -> str:
    lines = [f"REDACTED {source} -> {target} ({stats.entries} entries, none removed)"]
    rows = [
        ("headers", stats.headers),
        ("cookies", stats.cookies),
        ("query params", stats.query),
        ("params in URLs", stats.url_params),
        ("post data params", stats.post_params),
        ("post data text", stats.post_text),
        ("response bodies", stats.response_bodies),
        ("websocket frames", stats.websocket),
        ("URL passwords", stats.userinfo),
    ]
    for label, value in rows:
        if isinstance(value, Counter):
            lines.append(f"  {label:<17}{value.total():>5}  {_names(value)}".rstrip())
        else:
            lines.append(f"  {label:<17}{value:>5}")
    short = stats.secrets - stats.global_secrets
    lines.append(
        f"  {'value scrub':<17}{stats.scrub.total():>5}  {_names(stats.scrub)}".rstrip()
    )
    lines.append(
        f"    {stats.global_secrets} distinct values of {MIN_GLOBAL_LENGTH}+ chars "
        f"replaced everywhere; {short} shorter redacted by name only"
    )
    if not stats.not_scanned:
        lines.append("NOT SCANNED: none")
    else:
        n = len(stats.not_scanned)
        lines.append(f"NOT SCANNED: {n} bod{'ies' if n > 1 else 'y'} "
                     "(not redacted by name, may contain secrets)")
        lines.extend(f"  #{s.entry} {s.mime_type}: {s.reason}" for s in stats.not_scanned)
    return "\n".join(lines) + "\n"


def _names(counter: Counter) -> str:
    return ", ".join(f"{name} {n}" for name, n in sorted(counter.items()))
