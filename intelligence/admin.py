from django.contrib import admin
from .models import ThreatFeed, IndicatorOfCompromise, AnalystUpload

@admin.register(ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    list_display = ('name', 'source_type', 'location', 'historical_accuracy', 'is_active')

@admin.register(IndicatorOfCompromise)
class IndicatorOfCompromiseAdmin(admin.ModelAdmin):
    # Swapped out 'severity' for your new research metric verdicts
    list_display = ('indicator', 'ioc_type', 'composite_trust_score', 'final_verdict', 'total_mentions', 'last_seen')
    list_filter = ('ioc_type', 'final_verdict')
    search_fields = ('indicator', 'sources')

@admin.register(AnalystUpload)
class AnalystUploadAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'uploaded_at', 'processed_elements')