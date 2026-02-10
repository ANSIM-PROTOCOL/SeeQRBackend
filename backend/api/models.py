
import uuid
from django.db import models


class URLScanIOResponse(models.Model):
    url = models.URLField(unique=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    scan_id = models.UUIDField(default=uuid.uuid4, editable=False)
    response = models.JSONField(null=True, blank=True)
    screenshot = models.ImageField(upload_to='screenshots/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return str(self.url)


class EnumCategory:
    SCAN_URL = "scan_url"
    GENERATE_REPORT = "generate_report"


class OpenAIResponse(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ip = models.GenericIPAddressField(null=True, blank=True)
    category = models.CharField(max_length=255, null=True, blank=True)
    url = models.URLField(null=True, blank=True)
    # site_name = models.CharField(max_length=1000, null=True, blank=True)
    # threat_type = models.CharField(max_length=300, null=True, blank=True)
    # description = models.TextField(null=True, blank=True)
    # probability = models.IntegerField(null=True, blank=True)
    # reason = models.TextField(null=True, blank=True)
    prompt = models.TextField(null=True, blank=True)
    response = models.TextField(null=True, blank=True)
    response_detail = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return str(self.url)


class GeminiResponse(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ip = models.GenericIPAddressField(null=True, blank=True)
    category = models.CharField(max_length=255, null=True, blank=True)
    url = models.URLField(null=True, blank=True)
    # site_name = models.CharField(max_length=1000, null=True, blank=True)
    # threat_type = models.CharField(max_length=300, null=True, blank=True)
    # description = models.TextField(null=True, blank=True)
    # probability = models.IntegerField(null=True, blank=True)
    # reason = models.TextField(null=True, blank=True)
    prompt = models.TextField(null=True, blank=True)
    response = models.TextField(null=True, blank=True)
    response_detail = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return str(self.url)


class ScannedURL(models.Model):
    url = models.URLField(unique=True)
    site_name = models.CharField(max_length=1000, null=True, blank=True)
    threat_type = models.CharField(max_length=300, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    threat_score = models.IntegerField(null=True, blank=True)
    is_edit = models.BooleanField(default=False)
    model = models.CharField(max_length=255, null=True, blank=True)
    openai_response = models.ForeignKey(OpenAIResponse, on_delete=models.SET_NULL, null=True, blank=True)
    gemini_response = models.ForeignKey(GeminiResponse, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return str(self.url)


class GeneratedReport(models.Model):
    url = models.URLField(unique=True)
    site_name = models.CharField(max_length=1000, null=True, blank=True)
    threat_type = models.CharField(max_length=300, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    probability = models.IntegerField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    depth = models.JSONField(null=True, blank=True)
    is_edit = models.BooleanField(default=False)
    model = models.CharField(max_length=255, null=True, blank=True)
    openai_response = models.ForeignKey(OpenAIResponse, on_delete=models.SET_NULL, null=True, blank=True)
    gemini_response = models.ForeignKey(GeminiResponse, on_delete=models.SET_NULL, null=True, blank=True)
    is_processed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return str(self.url)


class ReportJob(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "PENDING"
        STARTED = "STARTED", "STARTED"
        SUCCESS = "SUCCESS", "SUCCESS"
        FAILURE = "FAILURE", "FAILURE"

    url = models.URLField(max_length=2000, unique=True)
    task_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True)

    last_error = models.TextField(blank=True, default="")

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    # 생성된 리포트와 연결(선택)
    generated_report = models.OneToOneField(
        "GeneratedReport",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="job",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_running(self) -> bool:
        return self.status in (self.Status.PENDING, self.Status.STARTED)


class Inquire(models.Model):
    class ActualThreat(models.TextChoices):
        SAFE = "safe", "안전"
        WARN = "warn", "주의"
        RISK = "risk", "위험"

    url = models.URLField()
    ai_threat_score = models.IntegerField(null=True, blank=True)
    ai_threat_label = models.CharField(max_length=32, null=True, blank=True)
    actual_threat = models.CharField(max_length=16, choices=ActualThreat.choices)
    details = models.TextField(blank=True)
    is_accept = models.BooleanField(default=False)
    accept_at = models.DateTimeField(null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.url)


class ScannedURLEditLog(models.Model):
    scanned_url = models.ForeignKey(ScannedURL, on_delete=models.CASCADE, related_name="edit_logs")
    site_name = models.CharField(max_length=1000, null=True, blank=True)
    threat_type = models.CharField(max_length=300, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    threat_score = models.IntegerField(null=True, blank=True)
    edited_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GeneratedReportEditLog(models.Model):
    generated_report = models.ForeignKey(GeneratedReport, on_delete=models.CASCADE, related_name="edit_logs")
    site_name = models.CharField(max_length=1000, null=True, blank=True)
    threat_type = models.CharField(max_length=300, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    probability = models.IntegerField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    edited_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

