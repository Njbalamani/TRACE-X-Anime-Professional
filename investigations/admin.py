from django.contrib import admin

from .models import AuditLog, Evidence, Finding, FindingEvidence, IntegrityRecord, Investigation, TimelineEvent


class EvidenceInline(admin.TabularInline):
    model = Evidence
    fields = ("title", "evidence_type", "sha256")
    readonly_fields = ("sha256",)
    extra = 0


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = ("case_number", "title", "status", "created_by", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("case_number", "title", "description")
    inlines = [EvidenceInline]


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ("title", "investigation", "evidence_type", "short_hash", "uploaded_at")
    list_filter = ("evidence_type", "uploaded_at")
    search_fields = ("title", "sha256")
    readonly_fields = ("sha256", "parsed_summary")


@admin.register(TimelineEvent)
class TimelineEventAdmin(admin.ModelAdmin):
    list_display = ("title", "investigation", "occurred_at", "severity", "source_ip")
    list_filter = ("severity", "occurred_at")
    search_fields = ("title", "description")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "investigation", "category", "severity", "confidence", "status")
    list_filter = ("category", "severity", "status")
    search_fields = ("title", "summary")


@admin.register(FindingEvidence)
class FindingEvidenceAdmin(admin.ModelAdmin):
    list_display = ("finding", "evidence", "relation")
    list_filter = ("relation",)


@admin.register(IntegrityRecord)
class IntegrityRecordAdmin(admin.ModelAdmin):
    list_display = ("height", "investigation", "object_type", "object_id", "short_hash", "created_at")
    search_fields = ("object_id", "block_hash")
    readonly_fields = ("block_hash", "prev_hash", "payload_hash")

    @admin.display(description="Block hash")
    def short_hash(self, obj):
        return f"{obj.block_hash[:16]}..."

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "investigation", "actor", "action", "object_type", "object_id")
    list_filter = ("action", "created_at")
    search_fields = ("object_id", "object_type", "detail")
    readonly_fields = ("created_at", "investigation", "actor", "action", "object_type", "object_id", "detail", "ip_address")
