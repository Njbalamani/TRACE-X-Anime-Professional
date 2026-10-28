"""Cryptographic fingerprints and blockchain-style hash-chain integrity records.

Every evidence item, timeline event and finding is fingerprinted with SHA-256.
Each investigation maintains a tamper-evident chain: block_hash covers the
object payload hash, the previous block hash and metadata, so any unauthorized
modification of investigation data breaks the chain at that height.
"""

import hashlib
import json

from django.utils import timezone

GENESIS_HASH = "0" * 64

OBJECT_SERIALIZERS = {}


def register_serializer(object_type):
    def deco(fn):
        OBJECT_SERIALIZERS[object_type] = fn
        return fn

    return deco


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_evidence(evidence) -> str:
    if evidence.file:
        evidence.file.open("rb")
        try:
            digest = sha256_bytes(evidence.file.read())
        finally:
            evidence.file.close()
    else:
        digest = sha256_text(evidence.content)
    return digest


def _payload(obj) -> str:
    serializer = OBJECT_SERIALIZERS.get(type(obj).__name__.lower())
    data = serializer(obj) if serializer else {"repr": repr(obj)}
    return sha256_text(json.dumps(data, sort_keys=True, default=str))


@register_serializer("evidence")
def _serialize_evidence(e):
    return {
        "pk": str(e.pk),
        "title": e.title,
        "evidence_type": e.evidence_type,
        "sha256": e.sha256,
        "content": e.content,
        "source": e.source,
        "collected_at": e.collected_at.isoformat() if e.collected_at else None,
    }


@register_serializer("timelineevent")
def _serialize_event(ev):
    return {
        "pk": str(ev.pk),
        "title": ev.title,
        "description": ev.description,
        "severity": ev.severity,
        "occurred_at": ev.occurred_at.isoformat() if ev.occurred_at else None,
        "source_ip": ev.source_ip,
        "evidence": str(ev.evidence_id) if ev.evidence_id else None,
    }


@register_serializer("finding")
def _serialize_finding(f):
    return {
        "pk": str(f.pk),
        "title": f.title,
        "category": f.category,
        "severity": f.severity,
        "confidence": f.confidence,
        "summary": f.summary,
        "explanation": f.explanation,
        "status": f.status,
        "links": sorted(
            [
                f"{l.evidence_id}:{l.relation}:{l.timeline_event_id}"
                for l in f.evidence_links.all()
            ]
        ),
    }


def compute_block_hash(payload_hash: str, prev_hash: str, height: int, created_at) -> str:
    material = f"{height}|{created_at.isoformat()}|{prev_hash}|{payload_hash}"
    return sha256_text(material)


def record_object(obj, investigation, user=None) -> "IntegrityRecord":
    from investigations.models import IntegrityRecord

    last = (
        IntegrityRecord.objects.filter(investigation=investigation).order_by("-height").first()
    )
    height = (last.height + 1) if last else 0
    prev_hash = last.block_hash if last else GENESIS_HASH
    payload_hash = _payload(obj)
    created_at = timezone.now()
    block_hash = compute_block_hash(payload_hash, prev_hash, height, created_at)
    record = IntegrityRecord.objects.create(
        investigation=investigation,
        object_type=type(obj).__name__.lower(),
        object_id=str(obj.pk),
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        block_hash=block_hash,
        height=height,
        recorded_by=user,
        created_at=created_at,
    )
    investigation.latest_chain_hash = block_hash
    investigation.save(update_fields=["latest_chain_hash", "updated_at"])
    return record


def rebuild_chain(investigation, user=None):
    """Rebuild the derived ledger from the current evidence/timeline/findings.

    Analysis is deterministic and regenerates AI objects, so retaining ledger
    records for deleted objects creates stale blocks. Rebuilding keeps one
    coherent chain while the independent tip anchor still detects truncation.
    """
    from investigations.models import Evidence, TimelineEvent, Finding, IntegrityRecord
    IntegrityRecord.objects.filter(investigation=investigation).delete()
    investigation.latest_chain_hash = ""
    investigation.save(update_fields=["latest_chain_hash", "updated_at"])
    for obj in Evidence.objects.filter(investigation=investigation).order_by("uploaded_at", "pk"):
        record_object(obj, investigation, user)
    for obj in TimelineEvent.objects.filter(investigation=investigation).order_by("occurred_at", "pk"):
        record_object(obj, investigation, user)
    for obj in Finding.objects.filter(investigation=investigation).order_by("created_at", "pk"):
        record_object(obj, investigation, user)


def _file_integrity(evidence):
    if not evidence.file:
        return {"checked": False, "valid": True, "reason": "No stored file; content fingerprint used"}
    try:
        actual = fingerprint_evidence(evidence)
    except (OSError, ValueError, FileNotFoundError):
        return {"checked": True, "valid": False, "reason": "Evidence file is missing or unreadable"}
    return {
        "checked": True,
        "valid": actual == evidence.sha256,
        "recorded_hash": evidence.sha256,
        "current_hash": actual,
        "reason": "Stored file matches acquisition hash" if actual == evidence.sha256 else "Evidence file changed after acquisition",
    }


def verify_chain_for(investigation) -> dict:
    """Recompute the whole chain for one investigation."""
    from investigations.models import IntegrityRecord

    records = IntegrityRecord.objects.filter(investigation=investigation).order_by("height")
    # Read the anchor independently from the caller object to avoid stale ORM instances.
    anchor = type(investigation).objects.only("latest_chain_hash").get(pk=investigation.pk).latest_chain_hash
    prev_hash = GENESIS_HASH
    broken = None
    for record in records:
        expected = compute_block_hash(record.payload_hash, prev_hash, record.height, record.created_at)
        if record.prev_hash != prev_hash or record.block_hash != expected:
            broken = {"height": record.height, "object": f"{record.object_type}:{record.object_id}"}
            break
        prev_hash = record.block_hash
    actual_tip = prev_hash if broken is None else None
    anchor_ok = bool(anchor) and actual_tip == anchor
    # A chain with records but no anchor is valid cryptographically but not
    # custody-anchored; new investigations always receive an anchor.
    anchored_valid = anchor_ok if records.exists() else not anchor
    return {
        "valid": broken is None and anchored_valid,
        "blocks": records.count(),
        "tip": actual_tip,
        "anchor": anchor,
        "anchor_valid": anchor_ok,
        "broken_at": broken,
        "reason": "Chain tip differs from independent anchor" if records.exists() and not anchor_ok else None,
    }


def verify_object(obj, investigation) -> dict:
    """Check that an object's current data still matches its recorded fingerprint."""
    from investigations.models import IntegrityRecord

    record = (
        IntegrityRecord.objects.filter(
            investigation=investigation, object_type=type(obj).__name__.lower(), object_id=str(obj.pk)
        )
        .order_by("-height")
        .first()
    )
    if record is None:
        return {"checked": False, "valid": None, "reason": "No integrity record yet"}
    current = _payload(obj)
    payload_valid = current == record.payload_hash
    file_result = _file_integrity(obj) if type(obj).__name__.lower() == "evidence" else {"valid": True, "checked": False}
    valid = payload_valid and file_result["valid"]
    return {
        "checked": True,
        "valid": valid,
        "payload_valid": payload_valid,
        "file_valid": file_result["valid"],
        "recorded_hash": record.payload_hash,
        "current_hash": current,
        "file_hash": file_result.get("current_hash"),
        "recorded_at": record.created_at.isoformat(),
        "reason": "Fingerprint matches" if valid else (file_result.get("reason") if not file_result["valid"] else "Payload changed since fingerprint was recorded"),
    }


def verify_investigation(investigation) -> dict:
    """Chain verification plus per-object fingerprint checks."""
    from investigations.models import Evidence, Finding, TimelineEvent

    chain = verify_chain_for(investigation)
    tampered = []
    groups = [
        ("evidence", Evidence.objects.filter(investigation=investigation)),
        ("timelineevent", TimelineEvent.objects.filter(investigation=investigation)),
        ("finding", Finding.objects.filter(investigation=investigation)),
    ]
    for name, qs in groups:
        for obj in qs:
            result = verify_object(obj, investigation)
            if result["checked"] and not result["valid"]:
                tampered.append(
                    {"object_type": name, "object_id": str(obj.pk), "label": str(obj)}
                )
    return {
        "valid": chain["valid"] and not tampered,
        "chain": chain,
        "tampered_objects": tampered,
        "checked_at": timezone.now().isoformat(),
    }
