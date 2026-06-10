from django.contrib import admin
# CORRECTED: Importing the exact models declared in your persistence layer
from .models import IndicatorOfCompromise, UploadArtifact

@admin.register(IndicatorOfCompromise)
class IndicatorOfCompromiseAdmin(admin.ModelAdmin):
    list_display = ('indicator', 'ioc_type', 'final_verdict', 'confidence', 'total_mentions', 'last_updated')
    list_filter = ('ioc_type', 'final_verdict')
    search_fields = ('indicator', 'tags')

@admin.register(UploadArtifact)
class UploadArtifactAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'uploaded_at', 'processed_elements')
    list_filter = ('uploaded_at',)
    search_fields = ('file_name',)