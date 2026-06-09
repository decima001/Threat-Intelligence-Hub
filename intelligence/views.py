from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from .models import IndicatorOfCompromise, ThreatFeed, AnalystUpload
from . import aggregator 

def dashboard(request):
    """Main panel displaying summary metrics, threat lists, and file uploads."""
    show_report_modal = False
    
    if request.method == "POST":
        if "trigger_sync" in request.POST:
            if hasattr(aggregator, 'run_intel_pipeline'):
                aggregator.run_intel_pipeline()
            elif hasattr(aggregator, 'sync_feeds'):
                aggregator.sync_feeds()
            messages.success(request, "Threat feed synchronization pipeline completed successfully.")
            context = get_dashboard_context()
            context['show_report_modal'] = True
            return render(request, 'intelligence/dashboard.html', context)
        
        elif "file_upload" in request.POST and request.FILES.get('analyst_file'):
            uploaded_file = request.FILES['analyst_file']
            file_name = uploaded_file.name
            
            try:
                file_text = uploaded_file.read().decode('utf-8', errors='ignore')
                file_size = len(file_text)
                
                found_count = 0
                if hasattr(aggregator, 'scan_uploaded_file_text'):
                    found_count = aggregator.scan_uploaded_file_text(file_text, file_name)
                elif hasattr(aggregator, 'process_file_text'):
                    found_count = aggregator.process_file_text(file_text, file_name)
                elif hasattr(aggregator, 'extract_indicators'):
                    found_count = aggregator.extract_indicators(file_text, file_name)
                elif hasattr(aggregator, 'extract_iocs'):
                    found_count = aggregator.extract_iocs(file_text, file_name)
                
                # Commit history entry
                AnalystUpload.objects.create(file_name=file_name, processed_elements=found_count)
                
                if found_count > 0:
                    messages.success(
                        request, 
                        f"🛡️ Scan Report: Successfully parsed '{file_name}' ({file_size} characters). "
                        f"Extracted and integrated {found_count} malicious indicators into your ledger!"
                    )
                else:
                    messages.warning(
                        request, 
                        f"⚠️ Scan Report: Successfully parsed '{file_name}' ({file_size} characters). "
                        f"Analysis complete, but 0 known threat patterns (IPs, Hashes, Domains) were identified."
                    )
                    
            except Exception as e:
                messages.error(request, f"❌ Ingestion Pipeline Failure: Unable to process file. Error: {str(e)}")
            
            show_report_modal = True

    context = get_dashboard_context()
    context['show_report_modal'] = show_report_modal
    return render(request, 'intelligence/dashboard.html', context)


def get_dashboard_context():
    """Helper method to generate baseline dashboard dataset metrics."""
    iocs = IndicatorOfCompromise.objects.all().order_by('-composite_trust_score')
    return {
        'iocs': iocs,
        'total_iocs': iocs.count(),
        'critical_severity': iocs.filter(final_verdict="Malicious (Critical)").count(),
        'high_severity': iocs.filter(final_verdict="High Risk").count(),
        'feeds_count': ThreatFeed.objects.filter(is_active=True).count(),
        # Uncapped query timeline history tracking
        'recent_uploads': AnalystUpload.objects.all().order_by('-uploaded_at'),
    }


def export_firewall(request):
    """Generates plaintext blocklists for firewalls/SIEM edge appliances."""
    ip_iocs = IndicatorOfCompromise.objects.filter(
        ioc_type__icontains='IP',
        final_verdict__in=['Malicious (Critical)', 'High Risk']
    ).values_list('indicator', flat=True).distinct()
    
    blocklist_content = "\n".join(ip_iocs)
    response = HttpResponse(blocklist_content, content_type="text/plain")
    response['Content-Disposition'] = 'attachment; filename="firewall_ip_blocklist.txt"'
    return response


def export_stix_bundle(request):
    """API endpoint that generates a strictly compliant STIX 2.1 JSON graph container."""
    django_iocs = IndicatorOfCompromise.objects.all()
    
    if hasattr(aggregator, 'convert_to_stix_bundle'):
        try:
            stix_json_string = aggregator.convert_to_stix_bundle(django_iocs)
            return HttpResponse(stix_json_string, content_type="application/json")
        except Exception as e:
            return JsonResponse({"error": f"STIX Generation Failure: {str(e)}"}, status=500)
            
    return JsonResponse({"error": "STIX conversion handler missing in aggregator module."}, status=501)

# Fail-safe URL mapping aliases
export_firewall_ips = export_firewall