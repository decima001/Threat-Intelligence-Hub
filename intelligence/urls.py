from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('export/firewall/', views.export_firewall_ips, name='export_firewall'),
    path('api/v1/stix/', views.export_stix_bundle, name='export_stix'),
]