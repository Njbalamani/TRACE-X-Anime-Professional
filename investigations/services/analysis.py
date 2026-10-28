"""TRACE-X analysis engine.

Parses heterogeneous evidence, reconstructs an attack timeline, correlates
activity across sources and emits natural-language findings, each linked to
the exact evidence (and often the exact excerpt) that supports it.
"""

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone as dt_timezone

from django.utils import timezone

from ..models import Evidence, Finding, FindingEvidence, TimelineEvent
from .integrity import fingerprint_evidence, rebuild_chain

TS_PATTERNS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%b %d %H:%M:%S",
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|xyz|top|co|uk|de)\b", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
USER_RE = re.compile(r"(?:user(?:name)?|account|login)[:= ]+([A-Za-z0-9._-]+)", re.I)

ATTACK_PATTERNS = [
    ("failed_login", re.compile(r"failed|failure|invalid (?:password|user)|authentication (?:error|failed)", re.I)),
    ("successful_login", re.compile(r"success(?:ful)?(?: login| auth)|(?:login|logon) (?:success|accepted)|session opened", re.I)),
    ("brute_force_hint", re.compile(r"brute[- ]?force|multiple failed|repeated failed", re.I)),
    ("malware", re.compile(r"malware|trojan|ransom|virus|c2|command.and.control", re.I)),
    ("phishing", re.compile(r"phish|credential harvest|spearphish", re.I)),
    ("exploit", re.compile(r"exploit|cve-\d{4}-\d+|rce|remote code", re.I)),
    ("privilege_escalation", re.compile(r"sudo|privilege|elevat|root|administrator|tampered group", re.I)),
    ("exfiltration", re.compile(r"exfil|upload|outbound.*(bytes|data)|data transfer", re.I)),
    ("scan", re.compile(r"scan|port (?:sweep|knock)|recon", re.I)),
    ("dns_tunnel", re.compile(r"dns (?:tunnel|anomal)|long txt query", re.I)),
]

CATEGORY_MAP = {
    "failed_login": ("credential_access", "high", "T1110"),
    "brute_force_hint": ("credential_access", "high", "T1110.001"),
    "successful_login": ("initial_access", "medium", "T1078"),
    "malware": ("execution", "critical", "T1204"),
    "phishing": ("initial_access", "high", "T1566"),
    "exploit": ("initial_access", "critical", "T1190"),
    "privilege_escalation": ("privilege_escalation", "high", "T1548"),
    "exfiltration": ("exfiltration", "critical", "T1041"),
    "scan": ("reconnaissance", "low", "T1595"),
    "dns_tunnel": ("exfiltration", "high", "T1048.003"),
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_timestamp(raw: str):
    raw = raw.strip().strip("[]")
    if not raw:
        return None
    # Preserve explicit offsets instead of silently treating local source time as UTC.
    iso_candidate = raw.replace(" UTC", "+00:00").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=dt_timezone.utc)
        return dt.astimezone(dt_timezone.utc)
    except ValueError:
        pass
    for fmt in TS_PATTERNS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=timezone.now().year)
            return dt.replace(tzinfo=dt_timezone.utc)
        except ValueError:
            continue
    return None


def _line_timestamp(line: str):
    match = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2})?|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}|\w{3} \d{1,2} \d{2}:\d{2}:\d{2})", line)
    return _parse_timestamp(match.group(1)) if match else None


def _severity_from_signals(flags) -> str:
    best = "info"
    for flag in flags:
        sev = CATEGORY_MAP.get(flag, (None, "info", ""))[1]
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[best]:
            best = sev
    return best


def _category_from_signals(flags) -> tuple:
    best = ("anomaly", "medium", "")
    for flag in flags:
        candidate = CATEGORY_MAP.get(flag)
        if candidate and SEVERITY_ORDER[candidate[1]] > SEVERITY_ORDER[best[1]]:
            best = candidate
    return best


def _excerpts(lines, limit=3):
    return [ln.strip() for ln in lines if ln.strip()][:limit]


# ---------------------------------------------------------------- parsers

def parse_log(evidence):
    events, flags, entities = [], set(), {"ips": set(), "users": set(), "hosts": set()}
    for line in evidence.content.splitlines():
        if not line.strip():
            continue
        matched = [name for name, rx in ATTACK_PATTERNS if rx.search(line)]
        flags.update(matched)
        ips = [ip for ip in IP_RE.findall(line) if _valid_ip(ip)]
        entities["ips"].update(ips)
        entities["users"].update(USER_RE.findall(line))
        if matched or ips:
            events.append(
                {
                    "occurred_at": _line_timestamp(line) or evidence.collected_at,
                    "title": _short_title(matched, line),
                    "description": line.strip()[:500],
                    "severity": _severity_from_signals(matched) if matched else "info",
                    "source_ip": ips[0] if ips else None,
                    "flags": matched,
                    "raw": line.strip(),
                }
            )
    return events, flags, entities


def parse_alert(evidence):
    events, flags, entities = [], set(), {"ips": set(), "users": set(), "hosts": set()}
    blocks = re.split(r"\n\s*\n", evidence.content.strip()) or [evidence.content]
    for block in blocks:
        matched = [name for name, rx in ATTACK_PATTERNS if rx.search(block)]
        flags.update(matched)
        ips = [ip for ip in IP_RE.findall(block) if _valid_ip(ip)]
        entities["ips"].update(ips)
        if not matched:
            matched = ["anomaly"]
            flags.add("anomaly")
        title_match = re.search(r"(?:rule|alert|signature|name)[:= ]+([^\n,]+)", block, re.I)
        events.append(
            {
                "occurred_at": _line_timestamp(block) or evidence.collected_at,
                "title": title_match.group(1).strip() if title_match else evidence.title,
                "description": block.strip()[:500],
                "severity": _severity_from_signals(matched),
                "source_ip": ips[0] if ips else None,
                "flags": matched,
                "raw": block.strip(),
            }
        )
    return events, flags, entities


def parse_email(evidence):
    events, flags, entities = [], set(), {"ips": set(), "users": set(), "domains": set()}
    text = evidence.content
    headers, _, body = text.partition("\n\n")
    fields = {}
    for line in headers.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip().lower()] = value.strip()
    body_flags = [name for name, rx in ATTACK_PATTERNS if rx.search(text)]
    flags.update(body_flags)
    urls = URL_RE.findall(body)
    domains = DOMAIN_RE.findall(body)
    entities["domains"].update(d.lower() for d in domains)
    sender = fields.get("from", "")
    sender_domain = sender.split("@")[-1].strip(">") if "@" in sender else ""
    received_domain = domains[0].lower() if domains else ""
    suspicious_links = bool(urls) and bool(body_flags)
    if suspicious_links or "phish" in flags:
        flags.add("phishing")
    if urls and not body_flags:
        flags.add("anomaly")
    summary = (
        f"Email '{fields.get('subject', evidence.title)}' from {sender or 'unknown'} "
        f"to {fields.get('to', 'unknown')}; {len(urls)} link(s), "
        f"{len(re.findall(r'attach', text, re.I))} attachment reference(s)."
    )
    if received_domain and sender_domain and received_domain not in sender_domain:
        summary += f" Body links point to {received_domain} which differs from sender domain {sender_domain}."
    events.append(
        {
            "occurred_at": _parse_timestamp(fields.get("date", "")) or evidence.collected_at,
            "title": f"Email received: {fields.get('subject', evidence.title)}",
            "description": summary,
            "severity": _severity_from_signals(flags) if flags else "medium",
            "source_ip": None,
            "flags": sorted(flags),
            "raw": (headers + "\n" + body).strip()[:1000],
        }
    )
    return events, flags, entities, summary, urls


def parse_network(evidence):
    events, flags, entities = [], set(), {"ips": set(), "users": set(), "destinations": defaultdict(int)}
    flows = defaultdict(list)
    bytes_out = defaultdict(int)
    for line in evidence.content.splitlines():
        if not line.strip():
            continue
        ips = [ip for ip in IP_RE.findall(line) if _valid_ip(ip)]
        entities["ips"].update(ips)
        matched = [name for name, rx in ATTACK_PATTERNS if rx.search(line)]
        flags.update(matched)
        port_match = re.search(r"(?:dport|dst.?port|port)[:= ]+(\d{1,5})", line, re.I)
        ts = _line_timestamp(line)
        if len(ips) >= 2:
            flows[ips[0]].append((ts, ips[1], int(port_match.group(1)) if port_match else None))
            entities["destinations"][ips[1]] += 1
        byte_match = re.search(r"(?:bytes|len|length)[:= ]+(\d+)", line, re.I)
        if byte_match and len(ips) >= 1:
            bytes_out[ips[0]] += int(byte_match.group(1))
        if matched or len(ips) >= 2:
            events.append(
                {
                    "occurred_at": ts or evidence.collected_at,
                    "title": _short_title(matched, line),
                    "description": line.strip()[:500],
                    "severity": _severity_from_signals(matched) if matched else "info",
                    "source_ip": ips[0] if ips else None,
                    "flags": matched,
                    "raw": line.strip(),
                }
            )
    # beaconing detection: same src/dst repeating at near-regular intervals
    for src, entries in flows.items():
        times = sorted(t for t, _, _ in entries if t)
        dsts = {d for _, d, _ in entries}
        if len(times) >= 5 and len(dsts) == 1:
            gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
            if gaps and max(gaps) - min(gaps) <= max(30.0, 0.25 * (sum(gaps) / len(gaps))):
                flags.add("c2")
                flags.add("beaconing")
                events.append(
                    {
                        "occurred_at": times[-1],
                        "title": f"Beaconing from {src} to {list(dsts)[0]}",
                        "description": (
                            f"{len(times)} connections to {list(dsts)[0]} at near-regular intervals "
                            f"(avg {sum(gaps)/len(gaps):.0f}s) — consistent with C2 beacon behavior."
                        ),
                        "severity": "high",
                        "source_ip": src,
                        "flags": ["c2", "beaconing"],
                        "raw": "",
                    }
                )
        if len(dsts) >= 15:
            flags.add("scan")
            events.append(
                {
                    "occurred_at": times[-1] if times else evidence.collected_at,
                    "title": f"Port/host scan from {src}",
                    "description": f"{src} contacted {len(dsts)} distinct destinations — scanning behavior.",
                    "severity": "medium",
                    "source_ip": src,
                    "flags": ["scan"],
                    "raw": "",
                }
            )
    for src, total in bytes_out.items():
        if total >= 1_000_000:
            flags.add("exfiltration")
            events.append(
                {
                    "occurred_at": evidence.collected_at,
                    "title": f"Large outbound transfer from {src}",
                    "description": f"{src} sent {total:,} bytes outbound in the captured window.",
                    "severity": "high",
                    "source_ip": src,
                    "flags": ["exfiltration"],
                    "raw": "",
                }
            )
    return events, flags, entities


def parse_generic(evidence):
    text = evidence.content or evidence.description or ""
    matched = [name for name, rx in ATTACK_PATTERNS if rx.search(text)]
    entities = {
        "ips": {ip for ip in IP_RE.findall(text) if _valid_ip(ip)},
        "users": set(USER_RE.findall(text)),
        "domains": set(d.lower() for d in DOMAIN_RE.findall(text)),
    }
    events = []
    if text.strip():
        events.append(
            {
                "occurred_at": evidence.collected_at,
                "title": evidence.title,
                "description": text.strip()[:500],
                "severity": _severity_from_signals(matched) if matched else "info",
                "source_ip": next(iter(entities["ips"]), None),
                "flags": matched,
                "raw": text.strip()[:1000],
            }
        )
    return events, set(matched), entities


def _valid_ip(ip):
    try:
        return ipaddress.ip_address(ip).version in (4, 6)
    except ValueError:
        return False


def _short_title(flags, line):
    labels = {
        "failed_login": "Failed login attempt",
        "successful_login": "Successful login",
        "brute_force_hint": "Repeated failed logins",
        "malware": "Malware activity detected",
        "phishing": "Phishing indicator",
        "exploit": "Exploit attempt",
        "privilege_escalation": "Privilege escalation",
        "exfiltration": "Data exfiltration indicator",
        "scan": "Scanning activity",
        "dns_tunnel": "Suspicious DNS activity",
    }
    for flag in flags:
        if flag in labels:
            return labels[flag]
    match = re.search(r"(?:action|event|msg|status)[:= ]+([^\s,;]+)", line, re.I)
    return match.group(1) if match else line.strip()[:80]


# ------------------------------------------------------------------ engine

def run_analysis(investigation, user=None) -> dict:
    """Full pipeline: parse -> timeline -> correlate -> findings -> integrity."""
    evidence_ids = list(investigation.evidence.values_list("id", flat=True))
    TimelineEvent.objects.filter(investigation=investigation, generated_by="ai").delete()
    Finding.objects.filter(investigation=investigation, generated_by="ai").delete()

    all_events = []
    flags_by_evidence = {}
    entities_by_evidence = {}
    summaries = {}
    ip_evidence = defaultdict(list)

    for evidence in investigation.evidence.all():
        if evidence.evidence_type == Evidence.TYPE_LOG:
            events, flags, entities = parse_log(evidence)
        elif evidence.evidence_type == Evidence.TYPE_ALERT:
            events, flags, entities = parse_alert(evidence)
        elif evidence.evidence_type == Evidence.TYPE_EMAIL:
            events, flags, entities, summary, _urls = parse_email(evidence)
            summaries[str(evidence.pk)] = summary
        elif evidence.evidence_type == Evidence.TYPE_NETWORK:
            events, flags, entities = parse_network(evidence)
        else:
            events, flags, entities = parse_generic(evidence)

        flags_by_evidence[str(evidence.pk)] = flags
        entities_by_evidence[str(evidence.pk)] = entities
        for event in events:
            event["_evidence"] = evidence
            all_events.append(event)
            if event.get("source_ip"):
                ip_evidence[event["source_ip"]].append(evidence)
        evidence.parsed_summary = {
            "flags": sorted(flags),
            "entities": {
                "ips": sorted(entities.get("ips", []))[:20],
                "users": sorted(entities.get("users", []))[:20],
                "domains": sorted(entities.get("domains", []))[:20],
            },
            "event_count": len(events),
        }
        evidence.save(update_fields=["parsed_summary"])
        if not evidence.sha256:
            evidence.sha256 = fingerprint_evidence(evidence)
            evidence.save(update_fields=["sha256"])

    all_events.sort(key=lambda e: e["occurred_at"])

    created_events = {}
    for event in all_events:
        ev = TimelineEvent.objects.create(
            investigation=investigation,
            evidence=event["_evidence"],
            occurred_at=event["occurred_at"],
            title=event["title"],
            description=event["description"],
            severity=event["severity"],
            source_ip=event.get("source_ip"),
            actor=", ".join(sorted(event.get("actor", "").split(", "))) if event.get("actor") else "",
            generated_by="ai",
            raw=event.get("raw", ""),
        )
        created_events[str(ev.pk)] = ev

    findings = _correlate(investigation, all_events, flags_by_evidence, entities_by_evidence, ip_evidence)

    report = _narrative(investigation, all_events, findings, summaries)
    rebuild_chain(investigation, user)
    investigation.last_analysis_at = timezone.now()
    severity_scores = {"info": 0, "low": 10, "medium": 35, "high": 70, "critical": 100}
    top_severity = max((severity_scores.get(f.severity, 0) for f in investigation.findings.all()), default=0)
    investigation.risk_score = min(100, top_severity + min(30, max(0, investigation.findings.count() - 1) * 5))
    investigation.status = investigation.STATUS_REPORTED
    investigation.save(update_fields=["status", "updated_at", "last_analysis_at", "risk_score"])
    return report


def _correlate(investigation, events, flags_by_evidence, entities_by_evidence, ip_evidence):
    """Turn correlated signals into findings, each with evidence links."""
    findings = []
    evidence_map = {str(e.pk): e for e in investigation.evidence.all()}
    event_by_evidence = defaultdict(list)
    for event in events:
        event_by_evidence[str(event["_evidence"].pk)].append(event)

    def add_finding(title, category, severity, confidence, summary, explanation, evidence_pks, relation="supports", excerpt_event=None):
        evidence_pks = [pk for pk in dict.fromkeys(evidence_pks) if pk in evidence_map]
        if not evidence_pks:
            return None
        finding = Finding.objects.create(
            investigation=investigation,
            title=title,
            category=category,
            severity=severity,
            confidence=round(confidence, 2),
            summary=summary,
            explanation=explanation,
            mitre_technique=_category_technique(category),
            generated_by="ai",
            created_by=None,
        )
        for pk in evidence_pks:
            evidence = evidence_map[pk]
            matching = [e for e in event_by_evidence.get(pk, []) if excerpt_event and excerpt_event in (e.get("title", "") + e.get("description", ""))]
            excerpt = matching[0]["raw"] if matching else (_excerpts(evidence.content.splitlines())[0] if evidence.content else evidence.description[:300])
            FindingEvidence.objects.create(
                finding=finding,
                evidence=evidence,
                relation=relation,
                rationale=_rationale(title, evidence),
                excerpt=excerpt[:500],
            )
        findings.append(finding)
        return finding

    flag_to_evidence = defaultdict(list)
    for pk, flags in flags_by_evidence.items():
        for flag in flags:
            flag_to_evidence[flag].append(pk)

    # 1. credential attacks — based on failed-login *events*, not evidence count,
    #    so a single log full of failures still triggers the rule
    failed = flag_to_evidence.get("failed_login", [])
    brute = flag_to_evidence.get("brute_force_hint", [])
    brute_union = list(dict.fromkeys(failed + brute))
    failed_events = [e for e in events if "failed_login" in e.get("flags", [])]
    # Require density: three failures from the same source within ten minutes,
    # or an explicit brute-force indicator. This avoids month-long false positives.
    clustered_failures = False
    by_ip = defaultdict(list)
    for event in failed_events:
        if event.get("source_ip"):
            by_ip[event["source_ip"]].append(event["occurred_at"])
    for timestamps in by_ip.values():
        timestamps = sorted(timestamps)
        for left in range(len(timestamps)):
            right = left
            while right < len(timestamps) and (timestamps[right] - timestamps[left]).total_seconds() <= 600:
                right += 1
            if right - left >= 3:
                clustered_failures = True
                break
        if clustered_failures:
            break
    if brute or clustered_failures:
        total_failures = len(failed_events) or sum(
            len(re.findall(r"fail", evidence_map[pk].content, re.I)) for pk in failed if evidence_map[pk].content
        )
        actor_ips = sorted(_ips_for(brute_union, entities_by_evidence))
        add_finding(
            title="Password guessing / brute-force attempt",
            category="credential_access",
            severity="high" if (brute or total_failures >= 5) else "medium",
            confidence=0.75 if brute else 0.6,
            summary=(
                f"{total_failures} failed authentication event(s)"
                + (f" originating from {', '.join(actor_ips)}" if actor_ips else "")
                + " across related evidence."
            ),
            explanation=(
                "Correlated repeated 'failed login' indicators across evidence sources. "
                "A high density of failures within a short window with a single source address "
                "is a strong signal of automated password guessing (MITRE T1110). "
                "Evidence examined: " + ", ".join(evidence_map[pk].title for pk in brute_union) + "."
            ),
            evidence_pks=brute_union,
        )

    # 2. successful access after failures (compromise indicator)
    success = flag_to_evidence.get("successful_login", [])
    if failed and success:
        actor_ips = sorted(_ips_for(failed + success, entities_by_evidence))
        add_finding(
            title="Possible successful compromise following failed attempts",
            category="initial_access",
            severity="high",
            confidence=0.65,
            summary=(
                "Failed and successful authentications appear in the same case"
                + (f" involving {', '.join(actor_ips)}" if actor_ips else "")
                + ", suggesting the guessed or stolen credential eventually worked."
            ),
            explanation=(
                "Sequence correlation: failed logins precede a successful login in the reconstructed "
                "timeline. When both occur for related sources/accounts, the most likely explanation "
                "is that the attacker obtained valid credentials (T1110 or T1078). The timeline view "
                "shows the ordering; each linked evidence item contains the raw events."
            ),
            evidence_pks=list(dict.fromkeys(failed + success)),
        )

    # 3. phishing
    phish = flag_to_evidence.get("phishing", [])
    if phish:
        add_finding(
            title="Phishing email delivered to the environment",
            category="initial_access",
            severity="high",
            confidence=0.7,
            summary=f"{len(phish)} email/alert artifact(s) exhibit phishing characteristics.",
            explanation=(
                "The email content contains links or attachments combined with social-engineering "
                "language indicators, and the linked domains differ from the sender domain. "
                "This matches MITRE T1566.001 (spearphishing link)."
            ),
            evidence_pks=phish,
        )

    # 4. malware / exploit
    for flag, title, cat in (
        ("malware", "Malware execution or detection", "execution"),
        ("exploit", "Exploit attempt against a service", "initial_access"),
    ):
        pks = flag_to_evidence.get(flag, [])
        if pks:
            category, severity, technique = CATEGORY_MAP[flag]
            add_finding(
                title=title,
                category=category,
                severity=severity,
                confidence=0.8,
                summary=f"{len(pks)} evidence item(s) contain {flag.replace('_', ' ')} indicators.",
                explanation=(
                    f"Detected signatures consistent with '{flag}' in the submitted artifacts. "
                    f"Expected ATT&CK technique: {technique}. Confidence is based on signature "
                    "match density across the linked evidence."
                ),
                evidence_pks=pks,
            )

    # 5. beaconing / C2
    beacon = flag_to_evidence.get("beaconing", []) + flag_to_evidence.get("c2", [])
    if beacon:
        pks = list(dict.fromkeys(beacon))
        add_finding(
            title="Command-and-control beaconing",
            category="anomaly",
            severity="critical",
            confidence=0.72,
            summary=f"Regular-interval outbound connections observed in {len(pks)} network artifact(s).",
            explanation=(
                "Connection timestamps show near-constant intervals to a single destination, which "
                "is characteristic of C2 keep-alive traffic rather than normal user activity. "
                "Correlated from network flow evidence; see the linked items for raw flow lines."
            ),
            evidence_pks=pks,
        )

    # 6. scanning / recon
    scan = flag_to_evidence.get("scan", [])
    if scan:
        add_finding(
            title="Reconnaissance scanning activity",
            category="reconnaissance",
            severity="medium",
            confidence=0.6,
            summary=f"{len(scan)} artifact(s) show scanning or broad connection attempts.",
            explanation=(
                "One source contacted many destinations/ports in a short window, matching "
                "discovery/scan behavior (T1595). Often precedes exploitation."
            ),
            evidence_pks=scan,
        )

    # 7. exfiltration
    exfil = flag_to_evidence.get("exfiltration", [])
    if exfil:
        add_finding(
            title="Suspected data exfiltration",
            category="exfiltration",
            severity="critical",
            confidence=0.68,
            summary=f"{len(exfil)} artifact(s) show large or unusual outbound data movement.",
            explanation=(
                "Outbound volume exceeds the baseline for the observed window, and/or DNS/upload "
                "patterns indicate data leaving the network (T1041/T1048). Linked evidence holds "
                "the flow records used for this estimate."
            ),
            evidence_pks=exfil,
        )

    # 8. privilege escalation
    priv = flag_to_evidence.get("privilege_escalation", [])
    if priv:
        add_finding(
            title="Privilege escalation activity",
            category="privilege_escalation",
            severity="high",
            confidence=0.62,
            summary=f"{len(priv)} artifact(s) reference elevated-privilege operations.",
            explanation=(
                "Elevated commands (sudo/administrator/root) or permission changes were observed "
                "outside a normal change window (T1548/T1068)."
            ),
            evidence_pks=priv,
        )

    # 9. cross-source correlation by shared IP
    shared = {ip: pks for ip, pks in ip_evidence.items() if len(set(pks)) >= 2}
    if shared and len(findings) >= 1:
        top_ip, top_pks = max(shared.items(), key=lambda kv: len(set(kv[1])))
        top_pks = list(dict.fromkeys(top_pks))
        add_finding(
            title=f"Shared source IP {top_ip} links multiple evidence sources",
            category="anomaly",
            severity="medium",
            confidence=0.7,
            summary=f"Address {top_ip} appears in {len(top_pks)} separate artifacts within this case.",
            explanation=(
                "Cross-source correlation: the same network address appears in independent evidence "
                "types, tying separate events into one activity chain. This is the primary link the "
                "AI used to group the timeline into a single actor path."
            ),
            evidence_pks=[str(pk.pk) for pk in top_pks],
            relation="corroborates",
        )

    # 10. integrity findings are created by the integrity service elsewhere
    return findings


def _ips_for(evidence_pks, entities_by_evidence):
    ips = set()
    for pk in evidence_pks:
        ips |= entities_by_evidence.get(pk, {}).get("ips", set())
    return ips


def _category_technique(category):
    for _flag, (cat, _sev, technique) in CATEGORY_MAP.items():
        if cat == category:
            return technique
    return ""


def _rationale(finding_title, evidence):
    return (
        f"'{evidence.title}' ({evidence.get_evidence_type_display()}) contains indicators that "
        f"directly support the conclusion '{finding_title}'. "
        f"Fingerprint {evidence.short_hash}."
    )


def _narrative(investigation, events, findings, summaries):
    ordered = sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity])
    lines = [f"Investigation {investigation.case_number}: {investigation.title}."]
    lines.append(
        f"Analyzed {investigation.evidence.count()} evidence item(s), producing "
        f"{len(events)} timeline event(s) and {len(findings)} finding(s)."
    )
    if events:
        lines.append(
            f"Activity spans {events[0]['occurred_at']:%Y-%m-%d %H:%M} to "
            f"{events[-1]['occurred_at']:%Y-%m-%d %H:%M} UTC."
        )
    if ordered:
        top = ordered[0]
        lines.append(
            f"Most severe conclusion: '{top.title}' ({top.severity}, confidence {top.confidence:.0%}) — "
            f"{top.summary}"
        )
    else:
        lines.append("No attack patterns were confidently identified in the submitted evidence.")
    lines.append(
        "Every conclusion above is traceable: open a finding to see the exact supporting "
        "evidence, excerpts and rationale."
    )
    return {
        "case_number": investigation.case_number,
        "events": len(events),
        "findings": [
            {
                "id": str(f.pk),
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "summary": f.summary,
                "explanation": f.explanation,
                "evidence_count": f.evidence_count,
            }
            for f in ordered
        ],
        "narrative": " ".join(lines),
        "evidence_summaries": summaries,
    }
