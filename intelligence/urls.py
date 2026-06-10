from django.urls import path
from . import views

urlpatterns = [
    # CORRECTED: Point to dashboard_view instead of dashboard
    path('', views.dashboard_view, name='dashboard'),
    
    # Target path endpoints for your pipeline exports
    path('export/stix/', views.export_stix_feed, name='export_stix'),
    path('export/firewall/', views.export_firewall_blocklist, name='export_firewall'),
]