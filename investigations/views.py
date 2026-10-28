import csv
import json

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.db.models import Count, Q, Case, When, IntegerField
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .forms import InvestigationForm
from .models import AuditLog, Evidence, Finding, Investigation, TimelineEvent
from .services.analysis import run_analysis
from .services.integrity import fingerprint_evidence, record_object, rebuild_chain, sha256_bytes, verify_investigation, verify_object


def _case_number():
    last = Investigation.objects.order_by("-created_at").first()
    seq = (Investigation.objects.count() or 0) + 1
    if last and last.case_number.startswith("TRX-"):
        try:
            seq = max(seq, int(last.case_number.split("-")[1]) + 1)
        except (IndexError, ValueError):
            pass
    return f"TRX-{seq:04d}"


def signup(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f"Welcome to TRACE-X, {user.username}. Your account is ready.")
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "registration/signup.html", {"form": form})


@login_required
def users_dashboard(request):
    users = (
        User.objects.annotate(
            investigation_count=Count("investigations", distinct=True),
            evidence_count=Count("evidence_uploads", distinct=True),
            finding_count=Count("findings", distinct=True),
        )
        .order_by("-is_active", "-last_login", "username")
    )
    context = {
        "users": users,
        "total_users": users.count(),
        "active_investigators": sum(1 for u in users if u.investigation_count or u.evidence_count),
        "total_cases": Investigation.objects.count(),
        "total_evidence": Evidence.objects.count(),
        "total_findings": Finding.objects.count(),
    }
    return render(request, "investigations/users.html", context)


MAX_EVIDENCE_BYTES = 25 * 1024 * 1024  # 25 MB per evidence file


def _can_access_case(request, investigation):
    return request.user.is_superuser or investigation.created_by_id == request.user.id


def _require_case(request, pk):
    investigation = get_object_or_404(Investigation, pk=pk)
    if not _can_access_case(request, investigation):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("You do not have access to this investigation.")
    return investigation


def _audit(request, investigation, action, obj=None, detail=None):
    AuditLog.objects.create(
        investigation=investigation, actor=request.user if request.user.is_authenticated else None,
        action=action, object_type=type(obj).__name__ if obj else "",
        object_id=str(obj.pk) if obj else "", detail=detail or {},
        ip_address=request.META.get("REMOTE_ADDR"),
    )


@login_required
def dashboard(request):
    case_filter = Q(created_by=request.user) if not request.user.is_superuser else Q()
    investigations = Investigation.objects.filter(case_filter).annotate(
        evidence_count=Count("evidence", distinct=True),
        finding_count=Count("findings", distinct=True),
        event_count=Count("timeline_events", distinct=True),
    )
    scoped = Investigation.objects.filter(case_filter)
    context = {
        "investigations": investigations[:10],
        "total_cases": scoped.count(),
        "total_evidence": Evidence.objects.filter(investigation__in=scoped).count(),
        "total_findings": Finding.objects.filter(investigation__in=scoped).count(),
        "total_events": TimelineEvent.objects.filter(investigation__in=scoped).count(),
        "critical_findings": Finding.objects.filter(investigation__in=scoped, severity="critical").count(),
        "high_findings": Finding.objects.filter(investigation__in=scoped, severity="high").count(),
        "verified_cases": sum(1 for case in scoped[:100] if case.integrity_status == "verified"),
        "average_risk": round(sum(case.risk_score for case in scoped) / scoped.count()) if scoped.exists() else 0,
    }
    return render(request, "investigations/dashboard.html", context)


@login_required
def investigation_list(request):
    investigations = Investigation.objects.filter(Q(created_by=request.user) | Q(created_by__isnull=True) if request.user.is_superuser else Q(created_by=request.user)).annotate(
        evidence_count=Count("evidence", distinct=True),
        finding_count=Count("findings", distinct=True),
    )
    query = request.GET.get("q", "").strip()
    if query:
        investigations = investigations.filter(
            Q(title__icontains=query) | Q(case_number__icontains=query) | Q(description__icontains=query)
        )
    return render(request, "investigations/investigation_list.html", {"investigations": investigations, "q": query})


@login_required
def investigation_create(request):
    if request.method == "POST":
        form = InvestigationForm(request.POST)
        if form.is_valid():
            investigation = form.save(commit=False)
            investigation.case_number = _case_number()
            investigation.created_by = request.user
            investigation.save()
            messages.success(request, f"Investigation {investigation.case_number} created.")
            return redirect("investigation_detail", pk=investigation.pk)
    else:
        form = InvestigationForm()
    return render(request, "investigations/investigation_form.html", {"form": form, "title": "New Investigation"})


@login_required
def investigation_detail(request, pk):
    investigation = _require_case(request, pk)
    _audit(request, investigation, AuditLog.ACTION_VIEW)
    evidence = investigation.evidence.all()
    events = investigation.timeline_events.select_related("evidence")
    findings = investigation.findings.annotate(link_count=Count("evidence_links"))
    integrity = verify_investigation(investigation)
    analysis = None
    if request.session.get("last_analysis") == str(investigation.pk):
        analysis = request.session.pop("last_analysis_report", None)
    return render(
        request,
        "investigations/investigation_detail.html",
        {
            "investigation": investigation,
            "evidence": evidence,
            "events": events,
            "findings": findings,
            "integrity": integrity,
            "analysis": analysis,
        },
    )


@login_required
@require_POST
def evidence_upload(request, pk):
    investigation = _require_case(request, pk)
    files = request.FILES.getlist("files")
    if not files:
        messages.error(request, "Attach at least one file.")
        return redirect("investigation_detail", pk=pk)
    created = 0
    for file in files:
        if file.size > MAX_EVIDENCE_BYTES:
            messages.error(request, f"Evidence file is too large: {file.name} (limit {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB).")
            continue
        raw = file.read()
        file.seek(0)
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
        ext = file.name.rsplit(".", 1)[-1].lower() if "." in file.name else ""
        evidence_type = {
            "log": Evidence.TYPE_LOG, "txt": Evidence.TYPE_LOG, "eml": Evidence.TYPE_EMAIL,
            "pcap": Evidence.TYPE_NETWORK, "csv": Evidence.TYPE_NETWORK,
            "png": Evidence.TYPE_SCREENSHOT, "jpg": Evidence.TYPE_SCREENSHOT, "jpeg": Evidence.TYPE_SCREENSHOT,
        }.get(ext, Evidence.TYPE_FILE)
        if ext == "json":
            # IDS/SIEM JSON is an alert artifact; generic JSON stays a file artifact.
            try:
                parsed = json.loads(content or "{}")
                alertish = isinstance(parsed, dict) and any(k in parsed for k in ("alert", "signature", "event_type", "rule", "severity"))
                evidence_type = Evidence.TYPE_ALERT if alertish or "ids" in file.name.lower() or "suricata" in file.name.lower() else Evidence.TYPE_FILE
            except json.JSONDecodeError:
                evidence_type = Evidence.TYPE_FILE
        if Evidence.objects.filter(investigation=investigation, sha256=sha256_bytes(raw)).exists():
            messages.warning(request, f"Duplicate evidence skipped: {file.name}")
            continue
        evidence = Evidence(
            investigation=investigation,
            title=file.name,
            evidence_type=evidence_type,
            file=file,
            content=content,
            source=file.name,
            uploaded_by=request.user,
        )
        # hash the bytes already read — fingerprint_evidence() would re-open
        # the uploaded stream and leave it closed for the storage save
        evidence.sha256 = sha256_bytes(raw)
        evidence.save()
        record_object(evidence, investigation, request.user)
        _audit(request, investigation, AuditLog.ACTION_CREATE, evidence, {"sha256": evidence.sha256, "filename": file.name})
        created += 1
    investigation.status = Investigation.STATUS_OPEN
    investigation.save(update_fields=["status", "updated_at"])
    messages.success(request, f"{created} evidence item(s) added and fingerprinted.")
    return redirect("investigation_detail", pk=pk)


@login_required
def evidence_detail(request, pk, evidence_pk):
    investigation = _require_case(request, pk)
    evidence = get_object_or_404(Evidence, pk=evidence_pk, investigation=investigation)
    integrity = verify_object(evidence, investigation)
    links = evidence.finding_links.select_related("finding")
    return render(
        request,
        "investigations/evidence_detail.html",
        {"investigation": investigation, "evidence": evidence, "integrity": integrity, "links": links},
    )


@login_required
@require_POST
def analyze(request, pk):
    investigation = _require_case(request, pk)
    if not investigation.evidence.exists():
        messages.error(request, "Add evidence before running AI analysis.")
        return redirect("investigation_detail", pk=pk)
    report = run_analysis(investigation, user=request.user)
    _audit(request, investigation, AuditLog.ACTION_ANALYZE, detail={"events": report["events"], "findings": len(report["findings"])})
    request.session["last_analysis"] = str(investigation.pk)
    request.session["last_analysis_report"] = report
    messages.success(request, f"Analysis complete: {report['events']} events, {len(report['findings'])} findings.")
    return redirect("investigation_detail", pk=pk)


@login_required
def finding_detail(request, pk, finding_pk):
    investigation = _require_case(request, pk)
    finding = get_object_or_404(
        Finding.objects.select_related("investigation").prefetch_related("evidence_links__evidence", "evidence_links__timeline_event"),
        pk=finding_pk,
        investigation=investigation,
    )
    integrity = verify_object(finding, investigation)
    related_events = investigation.timeline_events.filter(
        evidence_id__in=[link.evidence_id for link in finding.evidence_links.all()]
    )
    return render(
        request,
        "investigations/finding_detail.html",
        {
            "investigation": investigation,
            "finding": finding,
            "links": finding.evidence_links.select_related("evidence", "timeline_event"),
            "integrity": integrity,
            "related_events": related_events,
            "status_choices": Finding._meta.get_field("status").choices,
        },
    )


@login_required
@require_POST
def finding_status(request, pk, finding_pk):
    investigation = _require_case(request, pk)
    finding = get_object_or_404(Finding, pk=finding_pk, investigation=investigation)
    allowed_statuses = {value for value, _ in Finding._meta.get_field("status").choices}
    requested_status = request.POST.get("status", finding.status)
    if requested_status not in allowed_statuses:
        messages.error(request, "Invalid finding status.")
        return redirect("finding_detail", pk=pk, finding_pk=finding_pk)
    finding.status = requested_status
    finding.save(update_fields=["status"])
    rebuild_chain(investigation, request.user)
    _audit(request, investigation, AuditLog.ACTION_UPDATE, finding, {"status": finding.status})
    messages.success(request, "Finding status updated and the custody chain rebuilt.")
    return redirect("finding_detail", pk=pk, finding_pk=finding_pk)


@login_required
def integrity_view(request, pk):
    investigation = _require_case(request, pk)
    report = verify_investigation(investigation)
    _audit(request, investigation, AuditLog.ACTION_VERIFY, detail={"valid": report["valid"]})
    records = investigation.integrity_records.order_by("-height")
    return render(
        request,
        "investigations/integrity.html",
        {"investigation": investigation, "report": report, "records": records},
    )


@login_required
def evidence_download(request, pk, evidence_pk):
    investigation = _require_case(request, pk)
    evidence = get_object_or_404(Evidence, pk=evidence_pk, investigation=investigation)
    if not evidence.file:
        return JsonResponse({"error": "No file attached."}, status=404)
    from django.http import FileResponse
    _audit(request, investigation, AuditLog.ACTION_VIEW, evidence, {"download": True})
    response = FileResponse(evidence.file.open("rb"), as_attachment=True, filename=evidence.title)
    return response


@login_required
def case_report(request, pk):
    """Human-readable incident report suitable for browser print/PDF export."""
    investigation = _require_case(request, pk)
    report = verify_investigation(investigation)
    findings = investigation.findings.prefetch_related("evidence_links__evidence").order_by("-severity", "-created_at")
    events = investigation.timeline_events.select_related("evidence").order_by("occurred_at")
    _audit(request, investigation, AuditLog.ACTION_EXPORT, detail={"format": "html"})
    return render(request, "investigations/case_report.html", {
        "investigation": investigation, "report": report, "findings": findings,
        "events": events, "evidence": investigation.evidence.all(),
    })


@login_required
def ioc_export(request, pk):
    """Export unique IPs/domains observed in a case for threat-intel workflows."""
    investigation = _require_case(request, pk)
    values = {"ip": set(), "domain": set()}
    for evidence in investigation.evidence.all():
        summary = evidence.parsed_summary or {}
        entities = summary.get("entities", {})
        values["ip"].update(entities.get("ips", []))
        values["domain"].update(entities.get("domains", []))
        # Fall back to raw content when analysis has not run yet.
        import re
        values["ip"].update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", evidence.content or ""))
        values["domain"].update(re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|xyz|top|co|uk|de)\b", evidence.content or "", re.I))
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{investigation.case_number}-iocs.csv"'
    writer = csv.writer(response)
    writer.writerow(["type", "value", "case", "chain_status"])
    chain_status = "verified" if verify_investigation(investigation)["valid"] else "tampered"
    for kind in ("ip", "domain"):
        for value in sorted(values[kind]):
            writer.writerow([kind, value, investigation.case_number, chain_status])
    _audit(request, investigation, AuditLog.ACTION_EXPORT, detail={"format": "csv", "iocs": sum(map(len, values.values()))})
    return response


@login_required
def audit_log_view(request, pk):
    investigation = _require_case(request, pk)
    logs = investigation.audit_logs.select_related("actor").all()[:250]
    return render(request, "investigations/audit_log.html", {"investigation": investigation, "logs": logs})


@login_required
@require_POST
def case_status(request, pk):
    investigation = _require_case(request, pk)
    target = request.POST.get("status")
    allowed = {value for value, _ in Investigation.STATUS_CHOICES}
    if target not in allowed:
        messages.error(request, "Invalid case status.")
        return redirect("investigation_detail", pk=pk)
    investigation.status = target
    investigation.save(update_fields=["status", "updated_at"])
    _audit(request, investigation, AuditLog.ACTION_UPDATE, detail={"status": target})
    messages.success(request, f"Case status changed to {investigation.get_status_display()}.")
    return redirect("investigation_detail", pk=pk)


# ------------------------------------------------------------------ JSON API

@login_required
def api_investigations(request):
    data = [
        {
            "id": str(i.pk),
            "case_number": i.case_number,
            "title": i.title,
            "status": i.status,
            "evidence": i.evidence.count(),
            "findings": i.findings.count(),
            "timeline_events": i.timeline_events.count(),
            "created_at": i.created_at.isoformat(),
        }
        for i in (Investigation.objects.all() if request.user.is_superuser else Investigation.objects.filter(created_by=request.user))[:100]
    ]
    return JsonResponse({"investigations": data})


@login_required
def api_investigation_detail(request, pk):
    investigation = _require_case(request, pk)
    return JsonResponse(
        {
            "id": str(investigation.pk),
            "case_number": investigation.case_number,
            "title": investigation.title,
            "description": investigation.description,
            "status": investigation.status,
            "integrity": verify_investigation(investigation),
            "evidence": [
                {
                    "id": str(e.pk),
                    "title": e.title,
                    "type": e.evidence_type,
                    "sha256": e.sha256,
                    "collected_at": e.collected_at.isoformat(),
                }
                for e in investigation.evidence.all()
            ],
            "timeline": [
                {
                    "id": str(ev.pk),
                    "occurred_at": ev.occurred_at.isoformat(),
                    "title": ev.title,
                    "severity": ev.severity,
                    "source_ip": ev.source_ip,
                    "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
                }
                for ev in investigation.timeline_events.all()
            ],
            "findings": [
                {
                    "id": str(f.pk),
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "summary": f.summary,
                    "explanation": f.explanation,
                    "traceability": [
                        {
                            "evidence_id": str(l.evidence_id),
                            "evidence_title": l.evidence.title,
                            "relation": l.relation,
                            "rationale": l.rationale,
                            "excerpt": l.excerpt,
                        }
                        for l in f.evidence_links.all()
                    ],
                }
                for f in investigation.findings.all()
            ],
        }
    )


@login_required
@require_POST
def api_analyze(request, pk):
    investigation = _require_case(request, pk)
    if not investigation.evidence.exists():
        return JsonResponse({"error": "No evidence to analyze."}, status=400)
    report = run_analysis(investigation, user=request.user)
    _audit(request, investigation, AuditLog.ACTION_ANALYZE, detail={"events": report["events"], "findings": len(report["findings"])})
    return JsonResponse(report)


@login_required
def api_integrity(request, pk):
    investigation = _require_case(request, pk)
    report = verify_investigation(investigation)
    _audit(request, investigation, AuditLog.ACTION_VERIFY, detail={"valid": report["valid"]})
    return JsonResponse(report)


def api_health(request):
    return JsonResponse({"status": "ok", "service": "trace-x"})

@login_required
@require_POST
def sentinel_chat(request, pk):
    """Case-scoped AI investigator assistant. API credentials remain server-side."""
    investigation = _require_case(request, pk)
    try:
        body = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON request."}, status=400)

    user_message = str(body.get("message", "")).strip()
    history = body.get("history", [])
    if not user_message or len(user_message) > 4000:
        return JsonResponse({"error": "Message must contain 1–4000 characters."}, status=400)
    if not isinstance(history, list):
        history = []
    history = [m for m in history if isinstance(m, dict) and m.get("role") in {"user", "assistant"}][-10:]
    history.append({"role": "user", "content": user_message})

    # Lightweight per-session throttle to prevent accidental request storms.
    import time
    now = time.time()
    previous = float(request.session.get("sentinel_last_request", 0))
    if now - previous < 1.2:
        return JsonResponse({"error": "Please wait a moment before sending another message."}, status=429)
    request.session["sentinel_last_request"] = now

    from .services.ai_assistant import ask_sentinel
    try:
        answer = ask_sentinel(investigation, history)
    except RuntimeError as exc:
        return JsonResponse({"error": str(exc)}, status=502)

    _audit(request, investigation, AuditLog.ACTION_VIEW, detail={"ai_assistant": "sentinel_chat"})
    return JsonResponse({"answer": answer, "case_number": investigation.case_number})
