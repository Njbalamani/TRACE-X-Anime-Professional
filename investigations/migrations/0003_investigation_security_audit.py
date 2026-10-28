from django.conf import settings
import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("investigations", "0002_alter_integrityrecord_created_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="investigation",
            name="latest_chain_hash",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="investigation",
            name="last_analysis_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="investigation",
            name="risk_score",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("action", models.CharField(choices=[("view", "View"), ("create", "Create"), ("update", "Update"), ("delete", "Delete"), ("analyze", "Analyze"), ("verify", "Verify"), ("export", "Export")], max_length=16)),
                ("object_type", models.CharField(blank=True, max_length=64)),
                ("object_id", models.CharField(blank=True, max_length=64)),
                ("detail", models.JSONField(blank=True, default=dict)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ("investigation", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="audit_logs", to="investigations.investigation")),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
