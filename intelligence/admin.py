from django.contrib import admin
from .models import IndicatorOfCompromise, UploadArtifact

@admin.register(IndicatorOfCompromise)
class IndicatorOfCompromiseAdmin(admin.ModelAdmin):
    """
    Admin configuration interface layout for managing extracted threat indicators.
    """
    list_display = ('indicator', 'ioc_type', 'total_mentions', 'otx_pulses', 'final_verdict', 'confidence')
    list_filter = ('ioc_type', 'final_verdict')
    search_fields = ('indicator', 'tags')
    ordering = ('-total_mentions',)

@admin.register(UploadArtifact)
class UploadArtifactAdmin(admin.ModelAdmin):
    """
    Admin configuration interface layout for viewing historic log ingestions.
    """
    list_display = ('file_name', 'processed_elements', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('file_name',)
    ordering = ('-uploaded_at',)