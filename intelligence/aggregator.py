import re
from datetime import datetime
from django.conf import settings
from OTXv2 import OTXv2, IndicatorTypes
from .models import IndicatorOfCompromise

try:
    from stix2 import Indicator, Bundle
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False


def query_alienvault_otx(indicator, ioc_type):
    """
    Queries AlienVault Open Threat Exchange (OTX) API.
    Returns: (pulse_count, public_tags_list)
    """
    # CORRECTED: Target the variable name defined in settings.py
    api_key = getattr(settings, "ALIENVAULT_OTX_KEY", None)
    
    # Fallback checking logic
    if not api_key or "YOUR_ALIENVAULT" in api_key:
        print(f"[!] OTX API Key missing or default placeholder detected. Processing {indicator} locally.")
        return 0, []  

    # Map our local internal naming conventions to official SDK IndicatorTypes
    otx_type_map = {
        'IPv4 Address': IndicatorTypes.IPv4,
        'Domain/FQDN': IndicatorTypes.DOMAIN,
        'SHA-256 Hash': IndicatorTypes.FILE_HASH_SHA256,
        'MD5 Hash': IndicatorTypes.FILE_HASH_MD5
    }

    otx_type = otx_type_map.get(ioc_type)
    if not otx_type:
        return 0, []

    # RE-ADDED COMPLETION BLOCK WITH TRY / EXCEPT SAFETY WRAPPERS
    try:
        print(f"[+] Launching live OTX lookup stream for: {indicator}")
        otx = OTXv2(api_key)
        
        response = otx.get_indicator_details_by_section(
            indicator_type=otx_type, 
            indicator=indicator, 
            section='general'
        )
        
        pulse_info = response.get('pulse_info', {}) if isinstance(response, dict) else {}
        pulse_count = 0
        pulses_list = []
        
        if isinstance(pulse_info, dict):
            pulse_count = pulse_info.get('count', 0)
            pulses_list = pulse_info.get('pulses', [])
        
        tags = set()
        for pulse in pulses_list[:5]:  
            for tag in pulse.get('tags', []):
                tags.add(tag.lower())
                
        return pulse_count, list(tags)

    except Exception as e:
        import traceback
        print(f"[-] OTX API Connection Error for [{indicator}]: {str(e)}")
        traceback.print_exc()
        return 0, []

def scan_uploaded_file_text(file_content, file_name):
    """Ingests raw text log strings, interrogates OTX, and writes database objects."""
    if not file_content:
        return 0

    REGEX_PATTERNS = {
        'IPv4 Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'SHA-256 Hash': r'\b[a-fA-F0-9]{64}\b',
        'MD5 Hash': r'\b[a-fA-F0-9]{32}\b',
        'Domain/FQDN': r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]\.)+(?:[a-zA-Z]{2,63})\b'
    }

    found_indicators_count = 0
    extracted_data = {}

    for ioc_type, regex_str in REGEX_PATTERNS.items():
        matches = re.findall(regex_str, file_content)
        for match in matches:
            indicator = match.strip().lower() if ioc_type == 'Domain/FQDN' else match.strip()
            if indicator in ['127.0.0.1', '0.0.0.0'] or indicator.startswith('192.168.'):
                continue
            if indicator not in extracted_data:
                extracted_data[indicator] = {'type': ioc_type, 'count': 1}
            else:
                extracted_data[indicator]['count'] += 1

    for indicator, metadata in extracted_data.items():
        total_mentions = metadata['count']
        
        # LIVE INTERACTIVE ALIENVAULT FEED QUERIES
        otx_pulse_count, otx_tags = query_alienvault_otx(indicator, metadata['type'])
        
        # Dynamic Evaluation scoring based on global campaign visibility
        if otx_pulse_count > 0:
            relevance_score = 9.5 if otx_pulse_count > 3 else 8.5
            accuracy_score = 9.0
            
            # Formulate tag annotations to display transparent threat context
            tag_string = f" (Tags: {', '.join(otx_tags[:3])})" if otx_tags else ""
            source_attribution = f"OTX Community Campaign - {otx_pulse_count} Pulses{tag_string}"
        else:
            relevance_score = 7.0 if total_mentions > 2 else 5.0
            accuracy_score = 6.5
            source_attribution = f"Local Incident Upload ({file_name})"

        freshness_score = 9.0 if otx_pulse_count > 0 else 7.5
        completeness_score = 8.5 if otx_pulse_count > 0 else 6.0
        
        composite_trust_score = round(
            (relevance_score + accuracy_score + freshness_score + completeness_score) / 4, 2
        )
        
        if otx_pulse_count > 5 or composite_trust_score >= 8.0:
            final_verdict = 'Malicious (Critical)'
        elif otx_pulse_count > 0 or composite_trust_score >= 6.5:
            final_verdict = 'High Risk'
        else:
            final_verdict = 'Suspicious'

        ioc_obj, created = IndicatorOfCompromise.objects.update_or_create(
            indicator=indicator,
            defaults={
                'ioc_type': metadata['type'],
                'total_mentions': total_mentions,
                'sources': source_attribution,
                'relevance_score': relevance_score,
                'accuracy_score': accuracy_score,
                'freshness_score': freshness_score,
                'completeness_score': completeness_score,
                'composite_trust_score': composite_trust_score,
                'final_verdict': final_verdict,
                'last_seen': datetime.now()
            }
        )
        if created:
            found_indicators_count += 1

    return found_indicators_count


def convert_to_stix_bundle(django_iocs):
    """Converts local records into structured STIX 2.1 JSON schemas."""
    if not STIX_AVAILABLE:
        raise ImportError("The 'stix2' python module is not verified in this system.")

    stix_objects = []
    type_mapping = {
        'IPv4 Address': "ipv4-addr:value",
        'SHA-256 Hash': "file:hashes.'SHA-256'",
        'MD5 Hash': "file:hashes.'MD5'",
        'Domain/FQDN': "domain-name:value"
    }

    for ioc in django_iocs:
        stix_pattern_key = type_mapping.get(ioc.ioc_type)
        if not stix_pattern_key:
            continue
            
        stix_confidence = int(ioc.composite_trust_score * 10)
        
        stix_indicator = Indicator(
            name=f"Extracted {ioc.ioc_type}",
            description=f"Perimeter Platform intelligence. Feed Vector Context: {ioc.sources}",
            pattern=f"[{stix_pattern_key} = '{ioc.indicator}']",
            pattern_type="stix",
            valid_from=datetime.now(),
            confidence=stix_confidence,
            indicator_types=["malicious-activity"]
        )
        stix_objects.append(stix_indicator)
        
    stix_bundle = Bundle(objects=stix_objects)
    return stix_bundle.serialize(pretty=True)