import re
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from .models import IndicatorOfCompromise, UploadArtifact
from .aggregator import query_alienvault_otx  # Your corrected OTX code snippet

# Specialized regular expressions for exact log matching
IPV4_REGEX = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
SHA256_REGEX = r'\b[A-Fa-f0-9]{64}\b'
MD5_REGEX = r'\b[A-Fa-f0-9]{32}\b'

def calculate_severity_matrix(pulse_count, mentions):
    """Calculates granular risk profiles based on local hits and OTX feeds"""
    score = (pulse_count * 1.5) + (mentions * 0.8)
    confidence = min(int((score / 15) * 100), 100)
    
    if confidence >= 80 or pulse_count > 20:
        return 'Malicious (Critical)', max(confidence, 85)
    elif confidence >= 60 or pulse_count > 5:
        return 'High Risk', confidence
    elif confidence >= 30 or mentions > 3:
        return 'Suspicious', confidence
    return 'Informational', max(confidence, 15)

def dashboard_view(request):
    if request.method == "POST" and "file_upload" in request.POST:
        uploaded_file = request.FILES.get('analyst_file')
        if not uploaded_file:
            messages.error(request, "No file artifact uploaded.")
            return redirect('dashboard')

        try:
            file_content = uploaded_file.read().decode('utf-8', errors='ignore')
            
            # Extract indicators using regex
            found_ips = set(re.findall(IPV4_REGEX, file_content))
            found_sha256 = set(re.findall(SHA256_REGEX, file_content))
            found_md5 = set(re.findall(MD5_REGEX, file_content))

            # Filter out standard local loopback traffic
            filtered_ips = {ip for ip in found_ips if not ip.startswith(('127.', '192.168.', '10.', '172.16.'))}
            
            total_extracted = len(filtered_ips) + len(found_sha256) + len(found_md5)
            
            # Save the ingestion meta-history record
            artifact = UploadArtifact.objects.create(
                file_name=uploaded_file.name,
                processed_elements=total_extracted
            )

            # Process and persist indicators
            for ip in filtered_ips:
                process_indicator(ip, 'IPv4 Address')
            for h256 in found_sha256:
                process_indicator(h256, 'SHA-256 Hash')
            for hmd5 in found_md5:
                process_indicator(hmd5, 'MD5 Hash')

            messages.success(request, f"Successfully parsed '{uploaded_file.name}'. Isolated {total_extracted} unique external threat vectors.")
            return render(request, 'intelligence/dashboard.html', get_dashboard_context(show_modal=True))

        except Exception as e:
            messages.error(request, f"Pipeline Error processing file: {str(e)}")
            return redirect('dashboard')

    return render(request, 'intelligence/dashboard.html', get_dashboard_context())

def process_indicator(value, ioc_type):
    """Enriches and writes unique threats straight to our persistence engine"""
    ioc, created = IndicatorOfCompromise.objects.get_or_create(
        indicator=value,
        defaults={'ioc_type': ioc_type, 'total_mentions': 0}
    )
    
    ioc.total_mentions += 1

    # Enrich against live global APIs if it's a freshly uncovered threat
    if created or ioc.otx_pulses == 0:
        pulses, tags_list = query_alienvault_otx(value, ioc_type)
        ioc.otx_pulses = pulses
        ioc.tags = ",".join(tags_list) if tags_list else ""

    # Re-evaluate asset confidence thresholds on every ingest
    verdict, confidence_score = calculate_severity_matrix(ioc.otx_pulses, ioc.total_mentions)
    ioc.final_verdict = verdict
    ioc.confidence = confidence_score
    ioc.save()

def get_dashboard_context(show_modal=False):
    """Aggregates active telemetry calculations cleanly from sqlite database tables"""
    iocs = IndicatorOfCompromise.objects.all()
    
    return {
        'iocs': iocs,
        'recent_uploads': UploadArtifact.objects.all()[:5],
        'total_iocs': iocs.count(),
        'high_severity': iocs.filter(final_verdict__in=['High Risk', 'Malicious (Critical)']).count(),
        'feeds_count': 1,  # Active core pipeline integrations
        'show_report_modal': show_modal
    }

def export_stix_feed(request):
    """Generates structured STIX 2.1 Graph Bundles straight from persistent database rows"""
    objects = []
    iocs = IndicatorOfCompromise.objects.all()

    for ioc in iocs:
        # Create a compliant STIX 2.1 pattern string format
        pattern_map = {
            'IPv4 Address': f"[ipv4-addr:value = '{ioc.indicator}']",
            'SHA-256 Hash': f"[file:hashes.'SHA-256' = '{ioc.indicator}']",
            'MD5 Hash': f"[file:hashes.'MD5' = '{ioc.indicator}']"
        }
        
        pattern = pattern_map.get(ioc.ioc_type, f"[domain-name:value = '{ioc.indicator}']")
        clean_tags = f" (Tags: {ioc.tags})" if ioc.tags else ""

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc.id}a2c74-0cd1-49a5-811d-692cf35946a6",
            "name": f"Extracted {ioc.ioc_type}",
            "description": f"Perimeter platform intelligence. Threat Verdict: {ioc.final_verdict}{clean_tags}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "confidence": ioc.confidence
        })

    bundle = {
        "type": "bundle",
        "id": "bundle--04c78d4d-7fd9-4b46-ac81-c998d2ff6959",
        "objects": objects
    }
    return JsonResponse(bundle)

def export_firewall_blocklist(request):
    """Exposes plain-text output mapping for direct ingest by perimeter security gateways"""
    malicious_ips = IndicatorOfCompromise.objects.filter(
        ioc_type='IPv4 Address', 
        final_verdict__in=['High Risk', 'Malicious (Critical)']
    ).values_list('indicator', flat=True)
    
    response_text = "\n".join(malicious_ips)
    return HttpResponse(response_text, content_type="text/plain")