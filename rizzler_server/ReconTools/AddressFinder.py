import dns.resolver
import dns.zone
import dns.query
import asyncio
import logging
from typing import AsyncGenerator, Dict, Any
from datetime import datetime
from pydantic import ValidationError
from ReconTools.ToolSChemas import DnsRecordCollection, DnsEnumResult

# Configure logging
logger = logging.getLogger(__name__)

def resolve_record_type(domain: str, rtype: str) -> Dict[str, Any]:
    """Synchronously resolve a single DNS record type."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, rtype)
        records = [str(answer) for answer in answers]
        return {"record_type": rtype, "records": records}
    except Exception as e:
        return {"record_type": rtype, "error": str(e)}

def test_zone_transfer_single(domain: str, ns_server: str) -> Dict[str, Any]:
    """Synchronously attempt a zone transfer from a single NS server."""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
        zone_data = {str(name): node.to_text() for name, node in zone.nodes.items()}
        return {"ns_server": ns_server, "success": True, "data": zone_data}
    except Exception as e:
        return {"ns_server": ns_server, "success": False, "error": str(e)}

def analyze_spf_dmarc(dns_records: Dict[str, Any]) -> Dict[str, str]:
    """Analyze SPF and DMARC records from TXT records."""
    analysis = {}
    if 'TXT' in dns_records:
        for txt in dns_records['TXT']:
            if txt.startswith('v=spf1'):
                analysis['SPF'] = txt
                if 'all' not in txt:
                    analysis['SPF_warning'] = "No 'all' mechanism found - SPF may be incomplete."
                elif '-all' not in txt:
                    analysis['SPF_warning'] = "Soft fail or no fail policy - potential spoofing risk."
            elif txt.startswith('v=DMARC1'):
                analysis['DMARC'] = txt
                if 'p=none' in txt:
                    analysis['DMARC_warning'] = "DMARC policy set to 'none' - no enforcement."
    return analysis

async def AddressFinderForLLM(domain: str) -> AsyncGenerator[Dict[str, Any], None]:
    """Perform DNS enumeration and stream results asynchronously."""
    # Initial notification
    yield {"type": "enumeration_start", "domain": domain, "timestamp": datetime.now().isoformat()}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    all_dns_records = {}
    zone_transfer_results = []
    errors = []
    processing_domains = {domain}
    domains_to_process = [domain]
    MAX_CNAME_DEPTH = 5
    current_depth = 0

    # Process domains (main domain and CNAME targets)
    while domains_to_process and current_depth <= MAX_CNAME_DEPTH:
        current_domain = domains_to_process.pop(0)
        yield {"type": "domain_processing", "domain": current_domain}

        # Resolve DNS records concurrently
        tasks = [asyncio.to_thread(resolve_record_type, current_domain, rtype) for rtype in record_types]
        for task in asyncio.as_completed(tasks):
            result = await task
            rtype = result["record_type"]
            if "error" in result:
                errors.append(f"Error resolving {rtype} for {current_domain}: {result['error']}")
                yield {"type": "dns_record_error", "domain": current_domain, "record_type": rtype, "error": result["error"]}
            else:
                if current_domain == domain:
                    all_dns_records[rtype] = result["records"]
                else:
                    cname_key = f"CNAME_{current_domain}"
                    all_dns_records.setdefault(cname_key, {})[rtype] = result["records"]
                yield {"type": "dns_record", "domain": current_domain, "record_type": rtype, "records": result["records"]}

                # Handle CNAME targets
                if rtype == "CNAME" and current_domain == domain:
                    for cname_target in result["records"]:
                        if cname_target not in processing_domains:
                            processing_domains.add(cname_target)
                            domains_to_process.append(cname_target)
                            current_depth += 1

        # Zone transfers for main domain
        if current_domain == domain and "NS" in all_dns_records:
            ns_servers = all_dns_records["NS"]
            zt_tasks = [asyncio.to_thread(test_zone_transfer_single, domain, ns) for ns in ns_servers]
            for zt_task in asyncio.as_completed(zt_tasks):
                zt_result = await zt_task
                if zt_result["success"]:
                    zone_transfer_results.append(zt_result["data"])
                    yield {"type": "zone_transfer_success", "ns_server": zt_result["ns_server"], "data": zt_result["data"]}
                else:
                    errors.append(f"Zone transfer failed from {zt_result['ns_server']}: {zt_result['error']}")
                    yield {"type": "zone_transfer_failed", "ns_server": zt_result["ns_server"], "error": zt_result["error"]}

        # SPF/DMARC analysis for main domain
        if current_domain == domain and "TXT" in all_dns_records:
            spf_dmarc_analysis = analyze_spf_dmarc(all_dns_records)
            yield {"type": "spf_dmarc_analysis", "analysis": spf_dmarc_analysis}

    # Construct and yield final result
    logger.debug(f"all_dns_records before DnsRecordCollection: {all_dns_records}")
    final_records = DnsRecordCollection(
        dns_records=all_dns_records,
        zone_transfer_results=zone_transfer_results,
        spf_dmarc_analysis=spf_dmarc_analysis if 'spf_dmarc_analysis' in locals() else {}
    )
    logger.debug(f"DnsRecordCollection: {final_records}")
    final_result = DnsEnumResult(
        target=domain,
        records=final_records,
        errors=errors,
        timestamp=datetime.now().isoformat(),
        status="completed"
    )

    try:
        final_result_dict = final_result.model_dump()
        logger.debug(f"Final result dict: {final_result_dict}")
        yield {"__final_result__": True, "data": final_result_dict}
    except ValidationError as e:
        logger.error(f"DnsEnumerator final output validation failed: {e}")
        yield {"__final_result__": True, "data": {"error": f"Validation failed: {str(e)}"}}