from django.db import models

class UploadArtifact(models.Model):
    """Tracks historical log files dropped into the ingestion sandbox"""
    file_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    processed_elements = models.IntegerField(default=0)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.file_name} ({self.processed_elements} IoCs)"


class IndicatorOfCompromise(models.Model):
    """Stores unique threat indicators, validation metrics, and enrichment tags"""
    VERDICT_CHOICES = [
        ('Informational', 'Informational'),
        ('Suspicious', 'Suspicious'),
        ('High Risk', 'High Risk'),
        ('Malicious (Critical)', 'Malicious (Critical)'),
    ]

    indicator = models.CharField(max_length=255, unique=True)
    ioc_type = models.CharField(max_length=50)  # e.g., 'IPv4 Address', 'SHA-256 Hash'
    total_mentions = models.IntegerField(default=1)
    otx_pulses = models.IntegerField(default=0)
    tags = models.TextField(blank=True, help_text="Comma-separated OTX community tags")
    final_verdict = models.CharField(max_length=50, choices=VERDICT_CHOICES, default='Informational')
    confidence = models.IntegerField(default=50)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-total_mentions', '-confidence']

    def __str__(self):
        return f"{self.indicator} [{self.final_verdict}]"