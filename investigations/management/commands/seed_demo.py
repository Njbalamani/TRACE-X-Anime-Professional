from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone

from investigations.models import Evidence, Investigation
from investigations.services.analysis import run_analysis

DEMO_DIR = (
    __import__("pathlib").Path(__file__).resolve().parents[3] / "demo" / "evidence"
).resolve()


LOGINS = """
2026-09-28 02:13:07 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:12 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:18 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:25 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:31 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:36 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:44 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:52 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:13:58 src=203.0.113.44 user=admin status=FAILED password
2026-09-28 02:14:03 src=203.0.113.44 user=admin status=SUCCESSFUL login
2026-09-28 02:14:11 src=203.0.113.44 user=admin action=OPENED session
2026-09-28 02:22:40 src=203.0.113.44 user=admin command=sudo whoami elevation=root
2026-09-28 02:22:55 src=203.0.113.44 user=admin created=/tmp/dl.exe size=892344
"""

PHISH_EMAIL = """From: "Microsoft Security" <security@ms-updates-secure.ru>
To: finance@acme.example
Date: 2026-09-28 02:00:00
Subject: URGENT: mailbox quota exceeded - re-authenticate now

Dear employee,

Your mailbox is almost full. Click the link below to re-authenticate and keep your email:

https://ms-updates-secure.ru/reauth/office365/login?ref=finance

Login failed will result in suspension of your account within 24 hours.
Attachment: invoice_password_protected.pdf - enter your credentials to open.
"""

EMAIL_TRAIL = """
2026-09-28 02:05:15 proxy scan-detected URL https://ms-updates-secure.ru/reauth/office365/login?ref=finance
2026-09-28 02:05:19 proxy user=finance@acme.example resp=200 len=4189 password_field=present
"""

NETFLOW = """
2026-09-28 02:06:00 dst-ip=198.51.100.7 dport=443 bytes=1640
2026-09-28 02:06:30 dst-ip=198.51.100.7 dport=443 bytes=1204
2026-09-28 02:07:00 dst-ip=198.51.100.7 dport=443 bytes=1480
2026-09-28 02:07:30 dst-ip=198.51.100.7 dport=443 bytes=1122
2026-09-28 02:08:00 dst-ip=198.51.100.7 dport=443 bytes=1910
2026-09-28 02:08:30 dst-ip=198.51.100.7 dport=443 bytes=1033
2026-09-28 02:09:00 dst-ip=198.51.100.7 dport=443 bytes=1877
2026-09-28 02:09:30 dst-ip=198.51.100.7 dport=443 bytes=1160
2026-09-28 02:10:00 src=203.0.113.44 dst-ip=198.51.100.7 dport=443 bytes=24000000
"""

IDS_ALERT = """
2026-09-28 02:15:00 alert rule=ET MALWARE drive-by download signature=malware detected src=203.0.113.44 dst=198.51.100.7
severity=3 action=blocked
"""


class Command(BaseCommand):
    help = "Seed a demo TRACE-X investigation with realistic evidence and run AI analysis."

    def add_arguments(self, parser):
        parser.add_argument(
            "--username", default="investigator", help="Demo user to create / assume."
        )

    def handle(self, *args, **options):
        username = options["username"]
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_password("tracex123")
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Created user '{username}' (password tracex123)"))

        if Investigation.objects.filter(case_number="TRX-0001").exists():
            self.stdout.write(self.style.WARNING("Demo case TRX-0001 already exists. Skipping."))
            return

        investigation = Investigation.objects.create(
            case_number="TRX-0001",
            title="Phishing to credential abuse on email gateway",
            description=(
                "Employee-reported phishing email, gateway auth logs, proxy logs and a network "
                "capture. Objective: determine if the mailbox was compromised and credentials "
                "were used to obtain elevated access."
            ),
            created_by=user,
            status=Investigation.STATUS_REPORTED,
        )

        samples = [
            ("auth.log", Evidence.TYPE_LOG, LOGINS),
            ("phishing.eml", Evidence.TYPE_EMAIL, PHISH_EMAIL),
            ("proxy-trail.log", Evidence.TYPE_LOG, EMAIL_TRAIL),
            ("netflow-export.csv", Evidence.TYPE_NETWORK, NETFLOW),
            ("ids-alert.json", Evidence.TYPE_ALERT, IDS_ALERT),
        ]
        for title, evidence_type, content in samples:
            demo_file = DEMO_DIR / title
            if demo_file.exists():
                content = demo_file.read_text(encoding="utf-8")
            investigation.evidence.create(
                title=title,
                evidence_type=evidence_type,
                content=content,
                source="demo-seed",
            )

        for evidence in investigation.evidence.all():
            from investigations.services.integrity import fingerprint_evidence, record_object

            evidence.sha256 = fingerprint_evidence(evidence)
            evidence.save(update_fields=["sha256"])
            record_object(evidence, investigation, user)

        report = run_analysis(investigation, user=user)
        self.stdout.write(self.style.SUCCESS("Analysis complete."))
        self.stdout.write(report["narrative"])
        for finding in report["findings"]:
            self.stdout.write(
                f"  [{finding['severity'].upper():8}] {finding['title']} "
                f"(confidence {finding['confidence']:.0%}, {finding['evidence_count']} evidence)"
            )