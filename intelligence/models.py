from django.db import models

class ThreatFeed(models.Model):
    FEED_TYPES = [('url', 'Remote URL'), ('file', 'Manual Upload')]
    name = models.CharField(max_length=100)
    source_type = models.CharField(max_length=10, choices=FEED_TYPES, default='url')
    location = models.CharField(max_length=255)
    
    # Research Parameters for Feed Quality Attribution
    historical_accuracy = models.FloatField(default=0.85, help_text="Base accuracy rating of source (0.0 - 1.0)")
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class IndicatorOfCompromise(models.Model):
    IOC_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain Name'),
        ('hash', 'File Hash (SHA-256)'),
        ('ttp', 'Tactics & Techniques (TTP)'),
    ]

    indicator = models.CharField(max_length=255, unique=True)
    ioc_type = models.CharField(max_length=10, choices=IOC_TYPES)
    sources = models.TextField(help_text="Comma-separated tracking origins")
    total_mentions = models.IntegerField(default=1)
    
    # --- RESEARCH METRIC MATRIX SCORES (0.0 - 10.0) ---
    accuracy_score = models.FloatField(default=0.0)
    freshness_score = models.FloatField(default=0.0)
    completeness_score = models.FloatField(default=0.0)
    relevance_score = models.FloatField(default=0.0)
    
    # The final evaluation verdict calculated via your weighted formula
    composite_trust_score = models.FloatField(default=0.0, help_text="Weighted evaluation matrix index")
    final_verdict = models.CharField(max_length=50, default="Suspicious")
    
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"[{self.ioc_type.upper()}] {self.indicator} -> Score: {self.composite_trust_score}"

# --- MAKE SURE THIS IS SITTING AT THE BOTTOM OF THE FILE ---
class AnalystUpload(models.Model):
    """Tracks files uploaded manually by a SOC analyst for sandbox scanning."""
    file_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    processed_elements = models.IntegerField(default=0)
    
    def __str__(self):
        return f"{self.file_name} ({self.uploaded_at.strftime('%Y-%m-%d %H:%M')})"

class AnalystUpload(models.Model):
    file_name = models.CharField(max_length=255)
    processed_elements = models.IntegerField(default=0)
    uploaded_at = models.DateTimeField(auto_now_add=True) # <-- Ensures real-time tracking