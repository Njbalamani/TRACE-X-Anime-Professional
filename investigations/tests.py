"""TRACE-X test suite.

Covers: SHA-256 fingerprinting, evidence upload & validation, log/email/
network/alert parsing, event normalization, detection rules, correlation,
timeline generation, finding creation, evidence-to-finding traceability,
integrity hash chain & verification, UI views, JSON API and the full
end-to-end workflow.
"""

import hashlib
import json
import tempfile
from datetime import datetime
from datetime import timezone as datetime_timezone
from unittest import mock

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import (
    AuditLog,
    Evidence,
    Finding,
    FindingEvidence,
    IntegrityRecord,
    Investigation,
    TimelineEvent,
)
from .services import analysis as analysis_engine
from .services.analysis import parse_alert, parse_email, parse_log, parse_network, run_analysis
from .services.integrity import (
    GENESIS_HASH,
    compute_block_hash,
    fingerprint_evidence,
    record_object,
    sha256_bytes,
    sha256_text,
    verify_chain_for,
    verify_investigation,
    verify_object,
)

MEDIA_ROOT_TEMP = tempfile.mkdtemp(prefix="tracex-media-")

AUTH_LOG = """2026-09-28 02:13:07 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:12 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:18 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:25 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:31 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:14:03 src=203.0.113.44 user=admin status=SUCCESSFUL login
2026-09-28 02:22:40 src=203.0.113.44 user=admin command=sudo whoami elevation=root
"""

NETWORK_CSV = """2026-09-28 02:30:00 src=203.0.113.44 dst-ip=198.51.100.7 dport=443 bytes=24000000
"""

BEACON_CSV = "\n".join(
    f"2026-09-28 02:{6 + i // 2:02d}:{30 * (i % 2):02d} src=203.0.113.44 dst-ip=198.51.100.7 dport=443 bytes=1500"
    for i in range(6)
) + "\n"

IDS_ALERT = """2026-09-28 02:15:00 alert rule=ET MALWARE drive-by download signature=malware detected src=203.0.113.44 dst=198.51.100.7
severity=3 action=blocked
"""

PHISH_EMAIL = """From: "Microsoft Security" <security@ms-updates-secure.ru>
To: finance@acme.example
Date: 2026-09-28 02:00:00
Subject: URGENT: mailbox quota exceeded - re-authenticate now

Dear employee,

Your mailbox is almost full. Click the link below to re-authenticate:

https://ms-updates-secure.ru/reauth/office365/login?ref=finance

Login failed will result in suspension of your account within 24 hours.
"""


def make_investigation(**kwargs):
    defaults = {
        "title": "Test investigation",
        "description": "Test case",
        "case_number": f"TRX-T{Investigation.objects.count() + 1:04d}",
    }
    defaults.update(kwargs)
    return Investigation.objects.create(**defaults)


def make_evidence(investigation, content, evidence_type=Evidence.TYPE_LOG, title="auth.log", **kwargs):
    evidence = Evidence(
        investigation=investigation,
        title=title,
        evidence_type=evidence_type,
        content=content,
        **kwargs,
    )
    evidence.sha256 = fingerprint_evidence(evidence)
    evidence.save()
    return evidence


# ------------------------------------------------------------- hash & integrity


class SecurityRegressionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("custody", password="pw12345")
        self.client.force_login(self.user)
        self.investigation = Investigation.objects.create(case_number="TRX-CUST1", title="Custody", created_by=self.user)

    @override_settings(MEDIA_ROOT=MEDIA_ROOT_TEMP)
    def test_disk_file_tamper_is_detected(self):
        self.client.post(reverse("evidence_upload", args=[self.investigation.pk]), {"files": SimpleUploadedFile("tamper.log", b"original")})
        evidence = Evidence.objects.get(investigation=self.investigation)
        with open(evidence.file.path, "ab") as fh:
            fh.write(b"changed")
        report = verify_investigation(self.investigation)
        self.assertFalse(report["valid"])
        self.assertTrue(any(x["object_type"] == "evidence" for x in report["tampered_objects"]))

    def test_tip_truncation_is_detected(self):
        evidence = make_evidence(self.investigation, "hello")
        record_object(evidence, self.investigation, self.user)
        self.assertTrue(verify_chain_for(self.investigation)["valid"])
        IntegrityRecord.objects.order_by("-height").first().delete()
        self.assertFalse(verify_chain_for(self.investigation)["valid"])

    def test_invalid_finding_status_rejected(self):
        finding = Finding.objects.create(investigation=self.investigation, title="x", summary="x", status="suspected")
        response = self.client.post(reverse("finding_status", args=[self.investigation.pk, finding.pk]), {"status": "<script>x</script>"})
        finding.refresh_from_db()
        self.assertEqual(finding.status, "suspected")

    def test_reanalysis_does_not_accumulate_stale_blocks(self):
        make_evidence(self.investigation, AUTH_LOG)
        run_analysis(self.investigation, self.user)
        first = IntegrityRecord.objects.filter(investigation=self.investigation).count()
        run_analysis(self.investigation, self.user)
        second = IntegrityRecord.objects.filter(investigation=self.investigation).count()
        self.assertEqual(first, second)
        self.assertTrue(verify_chain_for(self.investigation)["valid"])


# ------------------------------------------------------------- hash & integrity


class HashingTests(TestCase):
    def test_sha256_text_known_vector(self):
        self.assertEqual(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sha256_bytes_known_vector(self):
        self.assertEqual(sha256_bytes(b"abc"), sha256_text("abc"))

    def test_fingerprint_evidence_by_content(self):
        evidence = Evidence(title="t", content="hello")
        self.assertEqual(evidence.sha256 or "", "")  # model field unset initially
        digest = fingerprint_evidence(evidence)
        self.assertEqual(digest, hashlib.sha256(b"hello").hexdigest())

    @override_settings(MEDIA_ROOT=MEDIA_ROOT_TEMP)
    def test_fingerprint_evidence_by_file(self):
        raw = b"raw evidence bytes \x00\x01"
        evidence = Evidence(title="f", content="")
        evidence.file.save("sample.bin", ContentFile(raw), save=False)
        self.assertEqual(fingerprint_evidence(evidence), hashlib.sha256(raw).hexdigest())

    def test_block_hash_deterministic(self):
        ts = datetime(2026, 1, 1, tzinfo=datetime_timezone.utc)
        h1 = compute_block_hash("payload", GENESIS_HASH, 0, ts)
        h2 = compute_block_hash("payload", GENESIS_HASH, 0, ts)
        self.assertEqual(h1, h2)
        self.assertNotEqual(compute_block_hash("payload2", GENESIS_HASH, 0, ts), h1)


class IntegrityChainTests(TestCase):
    def setUp(self):
        self.investigation = make_investigation()

    def test_chain_links_and_heights(self):
        evidence = make_evidence(self.investigation, "evidence body")
        record_object(evidence, self.investigation)
        event = TimelineEvent.objects.create(
            investigation=self.investigation,
            evidence=evidence,
            occurred_at=evidence.collected_at,
            title="event",
            generated_by="ai",
        )
        record_object(event, self.investigation)
        finding = Finding.objects.create(investigation=self.investigation, title="f", summary="s")
        record_object(finding, self.investigation)

        records = list(self.investigation.integrity_records.order_by("height"))
        self.assertEqual([r.height for r in records], [0, 1, 2])
        self.assertEqual(records[0].prev_hash, GENESIS_HASH)
        self.assertEqual(records[1].prev_hash, records[0].block_hash)
        self.assertEqual(records[2].prev_hash, records[1].block_hash)

        result = verify_chain_for(self.investigation)
        self.assertTrue(result["valid"])
        self.assertEqual(result["blocks"], 3)
        self.assertEqual(result["tip"], records[2].block_hash)

    def test_tampered_payload_detected(self):
        evidence = make_evidence(self.investigation, "original")
        record_object(evidence, self.investigation)
        record = self.investigation.integrity_records.first()
        record.payload_hash = "f" * 64  # simulate DB tampering
        record.save()
        result = verify_chain_for(self.investigation)
        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at"]["height"], record.height)

    def test_deleted_middle_record_breaks_chain(self):
        evidence = make_evidence(self.investigation, "one")
        record_object(evidence, self.investigation)
        event = TimelineEvent.objects.create(
            investigation=self.investigation, occurred_at=evidence.collected_at, title="e", generated_by="ai"
        )
        record_object(event, self.investigation)
        self.investigation.integrity_records.filter(height=0).delete()
        self.assertFalse(verify_chain_for(self.investigation)["valid"])

    def test_verify_object_detects_content_change(self):
        evidence = make_evidence(self.investigation, "before")
        record_object(evidence, self.investigation)
        self.assertTrue(verify_object(evidence, self.investigation)["valid"])
        evidence.content = "after"
        evidence.save()
        result = verify_object(evidence, self.investigation)
        self.assertFalse(result["valid"])
        self.assertNotEqual(result["recorded_hash"], result["current_hash"])

    def test_verify_object_without_record(self):
        evidence = make_evidence(self.investigation, "no record yet")
        result = verify_object(evidence, self.investigation)
        self.assertFalse(result["checked"])

    def test_verify_investigation_aggregates_tampered_objects(self):
        evidence = make_evidence(self.investigation, "before")
        record_object(evidence, self.investigation)
        evidence.content = "tampered"
        evidence.save()
        result = verify_investigation(self.investigation)
        self.assertFalse(result["valid"])
        self.assertEqual(result["tampered_objects"][0]["object_type"], "evidence")

    def test_investigation_integrity_status_property(self):
        self.assertEqual(self.investigation.integrity_status, "verified")
        evidence = make_evidence(self.investigation, "before")
        record_object(evidence, self.investigation)
        record = self.investigation.integrity_records.first()
        record.payload_hash = "f" * 64  # tampering with the ledger breaks the chain
        record.save()
        self.assertEqual(self.investigation.integrity_status, "tampered")


# ------------------------------------------------------------------- parsers


class ParserTests(TestCase):
    def setUp(self):
        self.investigation = make_investigation()

    def test_log_parser_normalizes_events(self):
        evidence = make_evidence(self.investigation, AUTH_LOG)
        events, flags, entities = parse_log(evidence)
        self.assertEqual(len(events), len([ln for ln in AUTH_LOG.splitlines() if ln.strip()]))
        first = events[0]
        self.assertEqual(first["title"], "Failed login attempt")
        self.assertEqual(first["source_ip"], "203.0.113.44")
        self.assertEqual(first["occurred_at"].strftime("%Y-%m-%d %H:%M:%S"), "2026-09-28 02:13:07")
        self.assertIn("failed_login", flags)
        self.assertIn("203.0.113.44", entities["ips"])
        self.assertIn("admin", entities["users"])

    def test_log_parser_privilege_escalation_flag(self):
        evidence = make_evidence(self.investigation, AUTH_LOG)
        _, flags, _ = parse_log(evidence)
        self.assertIn("privilege_escalation", flags)
        self.assertIn("successful_login", flags)

    def test_email_parser_extracts_fields_and_urls(self):
        evidence = make_evidence(self.investigation, PHISH_EMAIL, Evidence.TYPE_EMAIL, "phishing.eml")
        events, flags, entities, summary, urls = parse_email(evidence)
        self.assertEqual(len(events), 1)
        self.assertIn("phishing", flags)
        self.assertEqual(len(urls), 1)
        self.assertIn("ms-updates-secure.ru", entities["domains"])
        self.assertIn("ms-updates-secure.ru", summary)

    def test_network_parser_detects_beaconing(self):
        evidence = make_evidence(self.investigation, BEACON_CSV, Evidence.TYPE_NETWORK, "netflow.csv")
        events, flags, _ = parse_network(evidence)
        self.assertIn("beaconing", flags)
        self.assertIn("c2", flags)
        self.assertTrue(any("Beaconing" in e["title"] for e in events))

    def test_network_parser_detects_large_outbound_transfer(self):
        evidence = make_evidence(self.investigation, NETWORK_CSV, Evidence.TYPE_NETWORK, "netflow.csv")
        events, flags, _ = parse_network(evidence)
        self.assertIn("exfiltration", flags)
        self.assertTrue(any("Large outbound transfer" in e["title"] for e in events))

    def test_alert_parser_uses_rule_name(self):
        evidence = make_evidence(self.investigation, IDS_ALERT, Evidence.TYPE_ALERT, "ids.json")
        events, flags, _ = parse_alert(evidence)
        self.assertEqual(len(events), 1)
        self.assertIn("malware", flags)
        self.assertIn("ET MALWARE", events[0]["title"])

    def test_invalid_ips_are_discarded(self):
        evidence = make_evidence(self.investigation, "999.999.999.999 tried to login\n")
        events, _, entities = parse_log(evidence)
        self.assertEqual(entities["ips"], set())
        self.assertEqual(events, [])


# ------------------------------------------------------- detection & analysis


class DetectionAndAnalysisTests(TestCase):
    def setUp(self):
        self.investigation = make_investigation()
        self.auth = make_evidence(self.investigation, AUTH_LOG)
        self.network = make_evidence(self.investigation, NETWORK_CSV, Evidence.TYPE_NETWORK, "netflow.csv")
        self.alert = make_evidence(self.investigation, IDS_ALERT, Evidence.TYPE_ALERT, "ids.json")

    def _run(self):
        return run_analysis(self.investigation)

    def _finding_titles(self):
        return {f.title for f in self.investigation.findings.all()}

    def test_full_pipeline_counts_and_status(self):
        report = self._run()
        self.assertEqual(report["case_number"], self.investigation.case_number)
        self.assertGreater(report["events"], 0)
        self.assertGreater(len(report["findings"]), 0)
        self.investigation.refresh_from_db()
        self.assertEqual(self.investigation.status, Investigation.STATUS_REPORTED)
        self.assertEqual(
            self.investigation.timeline_events.filter(generated_by="ai").count(), report["events"]
        )

    def test_brute_force_detection(self):
        self._run()
        self.assertIn("Password guessing / brute-force attempt", self._finding_titles())

    def test_compromise_after_failures_detection(self):
        self._run()
        self.assertIn("Possible successful compromise following failed attempts", self._finding_titles())

    def test_privilege_escalation_detection(self):
        self._run()
        self.assertIn("Privilege escalation activity", self._finding_titles())

    def test_exfiltration_detection(self):
        self._run()
        self.assertIn("Suspected data exfiltration", self._finding_titles())

    def test_malware_detection(self):
        self._run()
        self.assertIn("Malware execution or detection", self._finding_titles())

    def test_cross_source_ip_correlation(self):
        self._run()
        self.assertIn(
            "Shared source IP 203.0.113.44 links multiple evidence sources", self._finding_titles()
        )

    def test_timeline_is_chronological_and_linked_to_evidence(self):
        self._run()
        events = list(self.investigation.timeline_events.all())
        self.assertTrue(events)
        timestamps = [e.occurred_at for e in events]
        self.assertEqual(timestamps, sorted(timestamps))
        for event in events:
            self.assertIsNotNone(event.evidence, "every normalized event must reference its source evidence")

    def test_every_finding_is_traceable_to_evidence(self):
        self._run()
        for finding in self.investigation.findings.all():
            self.assertGreater(finding.evidence_count, 0)
            for link in finding.evidence_links.all():
                self.assertTrue(link.rationale)
                self.assertTrue(link.excerpt)

    def test_analysis_is_idempotent(self):
        first = self._run()
        counts = (
            self.investigation.timeline_events.count(),
            self.investigation.findings.count(),
        )
        second = self._run()
        self.assertEqual(
            (
                self.investigation.timeline_events.count(),
                self.investigation.findings.count(),
            ),
            counts,
        )
        self.assertEqual(len(second["findings"]), len(first["findings"]))
        # the ledger is append-only: it grows with the re-run but stays valid
        self.assertTrue(verify_chain_for(self.investigation)["valid"])

    def test_manual_findings_survive_reanalysis(self):
        Finding.objects.create(investigation=self.investigation, title="Analyst note", summary="s", generated_by="manual")
        self._run()
        self.assertTrue(self.investigation.findings.filter(title="Analyst note").exists())

    def test_report_narrative_contains_case_number(self):
        report = self._run()
        self.assertIn(self.investigation.case_number, report["narrative"])

    def test_no_evidence_still_safe(self):
        empty = make_investigation(title="empty case")
        report = run_analysis(empty)
        self.assertEqual(report["events"], 0)
        self.assertEqual(report["findings"], [])
        self.assertIn("No attack patterns", report["narrative"])

    def test_finding_severity_ordering_in_report(self):
        report = self._run()
        severities = [f["severity"] for f in report["findings"]]
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        self.assertEqual(severities, sorted(severities, key=lambda s: -order[s]))


# ------------------------------------------------------------- signup & users


class SignupTests(TestCase):
    def test_signup_page_renders(self):
        response = self.client.get(reverse("signup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create investigator account")

    def test_signup_creates_and_logs_in_user(self):
        response = self.client.post(
            reverse("signup"),
            {"username": "newanalyst", "password1": "Royal!Gold42x", "password2": "Royal!Gold42x"},
            follow=True,
        )
        self.assertTrue(User.objects.filter(username="newanalyst").exists())
        self.assertEqual(str(response.context["user"]), "newanalyst")
        self.assertContains(response, "Welcome to TRACE-X")

    def test_signup_password_mismatch_rejected(self):
        response = self.client.post(
            reverse("signup"),
            {"username": "newanalyst", "password1": "Royal!Gold42x", "password2": "different1!"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="newanalyst").exists())

    def test_signup_duplicate_username_rejected(self):
        User.objects.create_user("taken", password="pw12345")
        self.client.post(
            reverse("signup"),
            {"username": "taken", "password1": "Royal!Gold42x", "password2": "Royal!Gold42x"},
        )
        self.assertEqual(User.objects.filter(username="taken").count(), 1)

    def test_authenticated_user_redirected_from_signup(self):
        user = User.objects.create_user("signed", password="pw12345")
        self.client.force_login(user)
        response = self.client.get(reverse("signup"))
        self.assertEqual(response.status_code, 302)


class UsersDashboardTests(TestCase):
    def test_requires_login(self):
        response = self.client.get(reverse("users_dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])

    def test_lists_users_with_activity_counts(self):
        investigator = User.objects.create_user("chief", password="pw12345")
        other = User.objects.create_user("rookie", password="pw12345")
        investigation = make_investigation(created_by=investigator, title="Chief case")
        make_evidence(investigation, AUTH_LOG)
        self.client.force_login(investigator)
        response = self.client.get(reverse("users_dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "chief")
        self.assertContains(response, "rookie")
        self.assertContains(response, "Active investigators")
        row = next(u for u in response.context["users"] if u.username == "chief")
        self.assertEqual(row.investigation_count, 1)
        self.assertEqual(row.evidence_count, 0)
        self.assertEqual(row.finding_count, 0)


# ------------------------------------------------------------------ UI views


@override_settings(MEDIA_ROOT=MEDIA_ROOT_TEMP)
class ViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("investigator", password="pw12345")
        self.client.force_login(self.user)
        self.investigation = make_investigation(created_by=self.user)

    def test_anonymous_user_redirected_to_login(self):
        self.client.logout()
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])

    def test_dashboard_renders_stats(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "TRACE-X")

    def test_create_investigation_assigns_case_number(self):
        response = self.client.post(
            reverse("investigation_create"), {"title": "New case", "description": "desc"}, follow=True
        )
        investigation = Investigation.objects.get(title="New case")
        self.assertContains(response, investigation.case_number)
        self.assertRegex(investigation.case_number, r"^TRX-\d{4}$")

    def test_investigation_list_search_filters(self):
        self.client.get(reverse("investigation_list"))
        response = self.client.get(reverse("investigation_list"), {"q": "Test investigation"})
        self.assertContains(response, self.investigation.title)
        response = self.client.get(reverse("investigation_list"), {"q": "zzz-no-match"})
        self.assertNotContains(response, self.investigation.title)

    def test_evidence_upload_hashes_file_and_records_integrity(self):
        raw = b"2026-10-07 10:00:00 src=203.0.113.10 user=admin status=FAILED login\n"
        upload = SimpleUploadedFile("auth.log", raw)
        response = self.client.post(
            reverse("evidence_upload", args=[self.investigation.pk]), {"files": upload}, follow=True
        )
        self.assertContains(response, "fingerprinted")
        evidence = Evidence.objects.get(investigation=self.investigation)
        self.assertEqual(evidence.evidence_type, Evidence.TYPE_LOG)
        self.assertEqual(evidence.sha256, hashlib.sha256(raw).hexdigest())
        self.assertIn("status=FAILED", evidence.content)
        self.assertTrue(
            IntegrityRecord.objects.filter(
                investigation=self.investigation, object_type="evidence", object_id=str(evidence.pk)
            ).exists()
        )

    def test_binary_upload_still_fingerprinted(self):
        upload = SimpleUploadedFile("artifact.bin", b"\x00\x01\x02\xff\xfe")
        self.client.post(reverse("evidence_upload", args=[self.investigation.pk]), {"files": upload})
        evidence = Evidence.objects.get(investigation=self.investigation)
        self.assertEqual(evidence.evidence_type, Evidence.TYPE_FILE)
        self.assertEqual(evidence.content, "")
        self.assertEqual(evidence.sha256, hashlib.sha256(b"\x00\x01\x02\xff\xfe").hexdigest())

    def test_upload_size_limit_enforced(self):
        from . import views

        raw = b"x" * 200
        with mock.patch.object(views, "MAX_EVIDENCE_BYTES", 100):
            response = self.client.post(
                reverse("evidence_upload", args=[self.investigation.pk]),
                {"files": SimpleUploadedFile("big.log", raw)},
                follow=True,
            )
        self.assertContains(response, "too large")
        self.assertFalse(Evidence.objects.filter(investigation=self.investigation).exists())

    def test_upload_requires_files(self):
        response = self.client.post(
            reverse("evidence_upload", args=[self.investigation.pk]), {}, follow=True
        )
        self.assertContains(response, "at least one file")

    def test_evidence_detail_shows_integrity(self):
        raw = b"evidence body"
        self.client.post(
            reverse("evidence_upload", args=[self.investigation.pk]),
            {"files": SimpleUploadedFile("a.log", raw)},
        )
        evidence = Evidence.objects.get(investigation=self.investigation)
        response = self.client.get(
            reverse("evidence_detail", args=[self.investigation.pk, evidence.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, evidence.sha256[:16])

    def test_analyze_requires_evidence(self):
        response = self.client.post(reverse("analyze", args=[self.investigation.pk]), follow=True)
        self.assertContains(response, "Add evidence before running")

    def test_analyze_produces_findings_page(self):
        make_evidence(self.investigation, AUTH_LOG)
        response = self.client.post(reverse("analyze", args=[self.investigation.pk]), follow=True)
        self.assertContains(response, "Analysis complete")
        self.assertContains(response, "Password guessing")
        finding = Finding.objects.filter(investigation=self.investigation).first()
        response = self.client.get(reverse("finding_detail", args=[self.investigation.pk, finding.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "auth.log")

    def test_finding_status_change_refingerprinted(self):
        make_evidence(self.investigation, AUTH_LOG)
        run_analysis(self.investigation, user=self.user)
        finding = Finding.objects.filter(investigation=self.investigation).first()
        blocks_before = IntegrityRecord.objects.filter(investigation=self.investigation).count()
        self.client.post(
            reverse("finding_status", args=[self.investigation.pk, finding.pk]), {"status": "confirmed"}, follow=True
        )
        finding.refresh_from_db()
        self.assertEqual(finding.status, "confirmed")
        self.assertEqual(
            IntegrityRecord.objects.filter(investigation=self.investigation).count(), blocks_before
        )
        self.assertTrue(verify_chain_for(self.investigation)["valid"])
        self.assertTrue(AuditLog.objects.filter(investigation=self.investigation, action="update").exists())

    def test_integrity_page_renders_chain(self):
        make_evidence(self.investigation, AUTH_LOG)
        self.client.post(reverse("evidence_upload", args=[self.investigation.pk]), {"files": SimpleUploadedFile("a.log", b"data")})
        run_analysis(self.investigation, user=self.user)
        response = self.client.get(reverse("integrity_view", args=[self.investigation.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "VERIFIED")


# --------------------------------------------------------------- JSON API


class ApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("apiuser", password="pw12345")
        self.investigation = make_investigation(created_by=self.user)
        self.client.force_login(self.user)

    def test_api_investigations_list(self):
        response = self.client.get(reverse("api_investigations"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["investigations"][0]["case_number"], self.investigation.case_number)

    def test_api_analyze_requires_post(self):
        response = self.client.get(reverse("api_analyze", args=[self.investigation.pk]))
        self.assertEqual(response.status_code, 405)

    def test_api_analyze_without_evidence_400(self):
        response = self.client.post(reverse("api_analyze", args=[self.investigation.pk]))
        self.assertEqual(response.status_code, 400)

    def test_api_investigation_detail_includes_traceability(self):
        make_evidence(self.investigation, AUTH_LOG)
        run_analysis(self.investigation)
        response = self.client.get(reverse("api_investigation_detail", args=[self.investigation.pk]))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["case_number"], self.investigation.case_number)
        self.assertTrue(data["integrity"]["valid"])
        self.assertTrue(data["findings"])
        for finding in data["findings"]:
            self.assertTrue(finding["traceability"], "finding must expose its evidence trail")
            self.assertTrue(finding["traceability"][0]["evidence_title"])

    def test_api_integrity_valid(self):
        make_evidence(self.investigation, AUTH_LOG)
        run_analysis(self.investigation)
        response = self.client.get(reverse("api_integrity", args=[self.investigation.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["valid"])

    def test_api_requires_authentication(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse("api_investigations")).status_code, 302)
        self.assertEqual(self.client.get(reverse("api_integrity", args=[self.investigation.pk])).status_code, 302)

    def test_case_isolated_between_users(self):
        other = User.objects.create_user("other", password="pw12345")
        self.client.force_login(other)
        self.assertEqual(self.client.get(reverse("investigation_detail", args=[self.investigation.pk])).status_code, 403)

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_login_shortcut_redirects(self):
        response = self.client.get("/login/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])


# ------------------------------------------------------------ full workflow


@override_settings(MEDIA_ROOT=MEDIA_ROOT_TEMP)
class FullWorkflowTests(TestCase):
    """Create -> upload -> hash -> parse -> detect -> correlate -> timeline ->
    findings -> link evidence -> verify integrity -> report."""

    def setUp(self):
        self.user = User.objects.create_user("investigator", password="pw12345")
        self.client.force_login(self.user)

    def test_complete_investigation_workflow(self):
        # 1. create investigation
        response = self.client.post(
            reverse("investigation_create"),
            {"title": "Account compromise on FIN-WS-04", "description": "Phishing suspected"},
            follow=True,
        )
        investigation = Investigation.objects.get(title="Account compromise on FIN-WS-04")
        self.assertEqual(investigation.case_number, "TRX-0001")

        # 2. upload evidence (hash + integrity record on arrival)
        self.client.post(
            reverse("evidence_upload", args=[investigation.pk]),
            {"files": [SimpleUploadedFile("auth.log", AUTH_LOG.encode()), SimpleUploadedFile("ids.json", IDS_ALERT.encode())]},
        )
        self.assertEqual(investigation.evidence.count(), 2)
        for evidence in investigation.evidence.all():
            self.assertEqual(len(evidence.sha256), 64)

        # 3. AI analysis: parse, detect, correlate, timeline, findings, links
        response = self.client.post(reverse("analyze", args=[investigation.pk]), follow=True)
        self.assertContains(response, "Analysis complete")
        self.assertGreater(investigation.timeline_events.count(), 0)

        # 4. findings are evidence-traceable
        findings = list(investigation.findings.all())
        self.assertGreaterEqual(len(findings), 3)
        titles = {f.title for f in findings}
        self.assertIn("Password guessing / brute-force attempt", titles)
        self.assertIn("Possible successful compromise following failed attempts", titles)
        for finding in findings:
            self.assertGreater(finding.evidence_count, 0)

        # 5. integrity verification passes after the full workflow
        report = verify_investigation(investigation)
        self.assertTrue(report["valid"], report)

        # 6. report / API view of the case
        response = self.client.get(reverse("api_investigation_detail", args=[investigation.pk]))
        data = response.json()
        self.assertTrue(data["timeline"])
        self.assertTrue(data["findings"])
        self.assertIn("case_number", data)

        # 7. integrity page shows the verified chain
        response = self.client.get(reverse("integrity_view", args=[investigation.pk]))
        self.assertContains(response, "VERIFIED")
