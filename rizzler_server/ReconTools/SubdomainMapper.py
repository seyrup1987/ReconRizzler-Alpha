# In tools/SubdomainMapper.py

import asyncio
import dns.resolver # Still potentially used by aiodns for initial resolver config
import aiodns
from datetime import datetime
# from duckduckgo_search import DDGS # REMOVED
import httpx # ADDED for SearXNG
from urllib.parse import urlparse
import logging
import requests
import os
import json # ADDED for SearXNG response parsing
import multiprocessing
from typing import List, Set, Dict, Any, AsyncGenerator, Optional # Added Optional
import re
import signal
import sys # ADDED for sys.exit in signal handler

from pydantic import ValidationError
from ReconTools.ToolSChemas import SubDomainEnumResult

# Logging configuration
LOG_DIRECTORY = os.path.join(os.path.dirname(__file__), '..', 'logs')
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)
LOG_FILE = os.path.join(LOG_DIRECTORY, f"subdomain_enumerator.log")

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.setLevel(logging.INFO)
    logger.propagate = False
    # file_h = logging.FileHandler(LOG_FILE) # Example: Keep file handler if desired
    # file_h.setLevel(logging.DEBUG)
    # console_h = logging.StreamHandler()
    # console_h.setLevel(logging.INFO)
    # logger.addHandler(file_h)
    # logger.addHandler(console_h)

logger.debug(f"SubdomainMapper logging initialized. Current level: {logger.getEffectiveLevel()}")


CONFIG = {
    "dns_timeout": 2.0,
    "http_timeout": 10, # Increased slightly for SearXNG/crt.sh robustness
    "task_timeout": 3600,
    "resolution_concurrency": 5000,
    "max_retries": 3,
    "backoff_factor": 2,
    "batch_size": 50000, # For brute-force DNS resolution batches
    "searxng_base_url": os.getenv("SEARXNG_BASE_URL", "http://localhost:7070") # Get from env or default
}

WORDLIST_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'config', 'SubdomainMapperConfig')
DEFAULT_WORDLIST = ["www", "mail", "ftp", "dev", "test", "admin", "api", "blog", "shop", "staging", "remote", "vpn", "portal", "cpanel", "webmail", "autodiscover", "owa"]

TIER_CONFIG = {
    "small": {"max_words": 50000, "description": "Common subdomains, very fast."},
    "medium": {"max_words": 500000, "description": "Extended list of common subdomains, moderate speed."},
    "large": {"max_words": 2500000, "description": "Large list of subdomains, slower."},
    "all": {"max_words": float('inf'), "description": "All available subdomains, can be very slow."}
}
_FULL_WORDLIST_CACHE: Optional[List[str]] = None

def load_wordlist(tier: str = "medium") -> List[str]:
    global _FULL_WORDLIST_CACHE
    logger.debug(f"Loading wordlist for tier: {tier}")

    if _FULL_WORDLIST_CACHE is None:
        logger.info(f"Populating full wordlist cache from {WORDLIST_FOLDER}...")
        wordlist_set = set(s.lower() for s in DEFAULT_WORDLIST) # Start with defaults, ensure lowercase
        try:
            if os.path.isdir(WORDLIST_FOLDER):
                for filename in os.listdir(WORDLIST_FOLDER):
                    if filename.endswith('.txt'):
                        file_path = os.path.join(WORDLIST_FOLDER, filename)
                        logger.debug(f"Reading wordlist file for cache: {file_path}")
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                                words = [line.strip().lower() for line in file if line.strip() and not line.startswith('#')]
                                wordlist_set.update(words)
                                logger.debug(f"Added {len(words)} words from {file_path} to cache set.")
                        except Exception as e:
                            logger.warning(f"Error reading {file_path} for cache: {e}")
            else:
                logger.warning(f"Wordlist folder {WORDLIST_FOLDER} does not exist. Using default wordlist for cache.")
        except Exception as e:
            logger.error(f"Error accessing wordlist folder {WORDLIST_FOLDER} for cache: {e}")
        
        if not wordlist_set:
            logger.warning("No valid words loaded into cache. Using default wordlist.")
            _FULL_WORDLIST_CACHE = sorted(list(set(s.lower() for s in DEFAULT_WORDLIST)))
        else:
            _FULL_WORDLIST_CACHE = sorted(list(wordlist_set))
        logger.info(f"Full wordlist cache populated with {len(_FULL_WORDLIST_CACHE)} unique subdomains.")

    tier_settings = TIER_CONFIG.get(tier.lower(), TIER_CONFIG["medium"])
    max_words = tier_settings["max_words"]

    if max_words == float('inf') or max_words >= len(_FULL_WORDLIST_CACHE):
        selected_words = _FULL_WORDLIST_CACHE
        logger.info(f"Using full wordlist ({len(selected_words)} words) for tier '{tier}'.")
    else:
        selected_words = _FULL_WORDLIST_CACHE[:int(max_words)] # Ensure max_words is int for slicing
        logger.info(f"Using tier '{tier}': {len(selected_words)} words (max: {int(max_words)}).")
    
    return selected_words

async def resolve_subdomain_async(subdomain: str, resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> List[str]:
    async with semaphore:
        logger.debug(f"Resolving subdomain (aiodns): {subdomain}")
        try:
            answers = await resolver.query(subdomain, 'A')
            ips = [answer.host for answer in answers]
            logger.debug(f"Resolved {subdomain} to {ips} (aiodns)")
            return ips
        except aiodns.error.DNSError as e:
            logger.debug(f"No resolution for {subdomain} (aiodns): {type(e).__name__} - {e.args[0] if e.args else str(e)}")
            return []
        except Exception as e: # Catch any other unexpected errors from aiodns
            logger.error(f"Unexpected error resolving {subdomain} (aiodns): {e}")
            return []

async def get_subdomains_from_search_async(domain: str, progress_tracker: Dict[str, Any], resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> List[str]:
    logger.info(f"Starting SearXNG web search for subdomains of {domain}")
    progress_tracker['search']['status'] = 'running'
    confirmed_subdomains = set()
    
    try:
        query = f"site:*.{domain} OR site:{domain}"
        params = {
            "q": query,
            "format": "json",
            "safesearch": 1,
            # "engines": "google,bing,duckduckgo,brave" # Optional: specify engines if SearXNG instance needs it
        }
        
        async with httpx.AsyncClient(timeout=CONFIG["http_timeout"]) as client:
            logger.debug(f"Querying SearXNG: {CONFIG['searxng_base_url']}/search with query: '{query}'")
            response = await client.get(f"{CONFIG['searxng_base_url']}/search", params=params)
            response.raise_for_status()
            searxng_results_json = response.json()

        raw_results = searxng_results_json.get('results', [])
        progress_tracker['search']['results_fetched'] = len(raw_results)
        logger.debug(f"Retrieved {len(raw_results)} search results from SearXNG for {domain}")
        
        potential_subdomains = set()
        for result in raw_results:
            url = result.get('url', '')
            if not url: continue
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc
                if netloc and (netloc.endswith("." + domain) or netloc == domain):
                    potential_subdomains.add(netloc.lower())
            except Exception as parse_exc:
                logger.debug(f"Could not parse URL from SearXNG result: {url} - {parse_exc}")
                continue
        
        progress_tracker['search']['potential'] = len(potential_subdomains)
        logger.debug(f"Found {len(potential_subdomains)} potential subdomains from SearXNG for {domain}")
        
        if potential_subdomains:
            resolution_tasks = [resolve_subdomain_async(sub, resolver, semaphore) for sub in potential_subdomains]
            resolved_ips_list = await asyncio.gather(*resolution_tasks, return_exceptions=True)

            for sub, res_ips in zip(potential_subdomains, resolved_ips_list):
                if isinstance(res_ips, list) and res_ips:
                    confirmed_subdomains.add(sub)
                    progress_tracker['search']['confirmed'] += 1
                    logger.debug(f"Confirmed subdomain from SearXNG: {sub} -> {res_ips}")
                elif isinstance(res_ips, Exception):
                    err_msg = f"DNS resolution failed for SearXNG-found {sub}: {str(res_ips)}"
                    logger.warning(err_msg)
                    progress_tracker['search']['errors'].append(err_msg)

        progress_tracker['search']['status'] = 'completed'
        logger.info(f"SearXNG search for {domain} completed. Confirmed {len(confirmed_subdomains)} subdomains")
        return list(confirmed_subdomains)

    except httpx.RequestError as e:
        err_msg = f"SearXNG request failed: {str(e)}"
        progress_tracker['search']['errors'].append(err_msg)
        logger.error(f"Error in SearXNG search for {domain}: {err_msg}")
    except httpx.HTTPStatusError as e:
        err_msg = f"SearXNG returned HTTP error {e.response.status_code}: {e.response.text[:200]}"
        progress_tracker['search']['errors'].append(err_msg)
        logger.error(f"Error in SearXNG search for {domain}: {err_msg}")
    except json.JSONDecodeError as e:
        err_msg = f"Failed to parse JSON response from SearXNG: {str(e)}"
        progress_tracker['search']['errors'].append(err_msg)
        logger.error(f"Error in SearXNG search for {domain}: {err_msg}")
    except Exception as e:
        err_msg = f"Unexpected error in SearXNG search for {domain}: {str(e)}"
        progress_tracker['search']['errors'].append(err_msg)
        logger.error(err_msg, exc_info=True)
    
    progress_tracker['search']['status'] = 'failed'
    return list(confirmed_subdomains)


async def get_subdomains_from_dns_async(domain: str, progress_tracker: Dict[str, Any], resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> List[str]:
    logger.info(f"Starting DNS record query for subdomains of {domain}")
    record_types = ['NS', 'MX', 'SRV', 'TXT']
    subdomains = set()

    for rec_type in record_types:
        logger.debug(f"Querying {rec_type} records for {domain} (aiodns)")
        try:
            answers = await resolver.query(domain, rec_type)
            for rdata in answers:
                target_str = ""
                if rec_type == 'NS': target_str = str(rdata.host).rstrip('.').lower()
                elif rec_type == 'MX': target_str = str(rdata.exchange).rstrip('.').lower() # aiodns MX record has 'exchange'
                elif rec_type == 'SRV': target_str = str(rdata.host).rstrip('.').lower()
                elif rec_type == 'TXT':
                    txt_contents = rdata.text if isinstance(rdata.text, (list, tuple)) else [rdata.text]
                    for txt_part_bytes in txt_contents: # aiodns TXT rdata.text can be bytes or list/tuple of bytes
                        txt_part = txt_part_bytes.decode('utf-8', 'ignore') if isinstance(txt_part_bytes, bytes) else str(txt_part_bytes)
                        
                        # Improved regex to find hostnames more reliably
                        # This regex looks for patterns like subdomain.domain.com or subdomain.subdomain.domain.com
                        # It tries to avoid matching parts of sentences or generic words.
                        # It's still heuristic.
                        pattern = r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain)
                        found_hostnames = re.findall(pattern, txt_part)
                        
                        for hn_match in found_hostnames: # hn_match is a full matched hostname string
                            hn = hn_match.rstrip('.').lower()
                            if hn.endswith("." + domain) or hn == domain: # Redundant check but safe
                                subdomains.add(hn)
                    continue 

                if target_str and (target_str.endswith("." + domain) or target_str == domain):
                    subdomains.add(target_str)
                    progress_tracker['dns']['potential'] += 1 # Count unique potentials
                    logger.debug(f"Found potential subdomain from {rec_type}: {target_str}")
        except aiodns.error.DNSError as e:
            logger.debug(f"No {rec_type} records found for {domain} (aiodns): {type(e).__name__} - {e.args[0] if e.args else str(e)}")
        except Exception as e:
            err_msg = f"Error querying {rec_type} for {domain} (aiodns): {e}"
            progress_tracker['dns']['errors'].append(err_msg)
            logger.error(err_msg)
    
    progress_tracker['dns']['potential'] = len(subdomains) # Update potential count based on unique set
    logger.debug(f"Found {len(subdomains)} potential subdomains from DNS records for {domain}")
    
    confirmed_subdomains = set()
    if subdomains:
        resolution_tasks = [resolve_subdomain_async(sub, resolver, semaphore) for sub in subdomains]
        resolved_ips_list = await asyncio.gather(*resolution_tasks, return_exceptions=True)

        for sub, res_ips in zip(subdomains, resolved_ips_list):
            if isinstance(res_ips, list) and res_ips:
                confirmed_subdomains.add(sub)
                progress_tracker['dns']['confirmed'] += 1
            elif isinstance(res_ips, Exception):
                err_msg = f"Error resolving DNS-derived subdomain {sub} (aiodns): {res_ips}"
                logger.warning(err_msg)
                progress_tracker['dns']['errors'].append(err_msg)


    progress_tracker['dns']['status'] = 'completed'
    logger.info(f"DNS query for {domain} completed. Confirmed {len(confirmed_subdomains)} subdomains")
    return list(confirmed_subdomains)

async def brute_force_subdomains(domain: str, wordlist: List[str], progress_tracker: Dict[str, Any], resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> AsyncGenerator[Dict[str, Any], None]:
    logger.info(f"Starting brute-force enumeration for {domain} using a wordlist of {len(wordlist)} items.")
    found_subdomains_set = set()
    
    batch_size = CONFIG["batch_size"]
    total_words = len(wordlist)
    num_batches = (total_words + batch_size - 1) // batch_size
    progress_tracker['brute']['total_to_check'] = total_words
    progress_tracker['brute']['checked_count'] = 0
    
    yield {
        "method": "brute_force", "status": "starting", 
        "message": f"Starting brute-force with {total_words} words in {num_batches} batches.",
        "total_words": total_words, "batch_size": batch_size
    }

    for i in range(0, total_words, batch_size):
        batch_words = wordlist[i:i + batch_size]
        tasks = []
        subdomains_in_batch = [f"{word}.{domain}".lower() for word in batch_words]

        for sub_to_check in subdomains_in_batch:
            tasks.append(resolve_subdomain_async(sub_to_check, resolver, semaphore))
        
        results_for_batch = await asyncio.gather(*tasks, return_exceptions=True)
        
        batch_confirmed_count = 0
        for idx, res_ips in enumerate(results_for_batch):
            sub_checked = subdomains_in_batch[idx]
            progress_tracker['brute']['checked_count'] += 1
            if isinstance(res_ips, list) and res_ips:
                if sub_checked not in found_subdomains_set:
                    found_subdomains_set.add(sub_checked)
                    batch_confirmed_count +=1
                    progress_tracker['brute']['confirmed'] += 1
                    logger.debug(f"Brute-force confirmed: {sub_checked} -> {res_ips}")
                    yield {"method": "brute_force", "status": "found", "subdomain": sub_checked, "ips": res_ips}
            elif isinstance(res_ips, Exception):
                # Do not add resolution errors to progress_tracker['brute']['errors'] here,
                # as "no resolution" is expected for most brute-force attempts.
                # Only log them at debug level.
                logger.debug(f"Brute-force resolution error/no record for {sub_checked} (aiodns): {res_ips}")
        
        logger.debug(f"Batch {i//batch_size + 1}/{num_batches} processed.")
        yield {
            "method": "brute_force", "status": "progress",
            "message": f"Batch {i//batch_size + 1}/{num_batches} processed. {batch_confirmed_count} new subdomains found in this batch.",
            "checked_so_far": progress_tracker['brute']['checked_count'],
            "confirmed_so_far": progress_tracker['brute']['confirmed']
        }
        await asyncio.sleep(0.05)

    progress_tracker['brute']['status'] = 'completed'
    logger.info(f"Brute-force for {domain} completed. Found {len(found_subdomains_set)} subdomains")

async def fetch_crtsh_subdomains(domain: str, progress_tracker: Dict[str, Any], resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> AsyncGenerator[Dict[str, Any], None]:
    logger.info(f"Starting crt.sh subdomain fetching for {domain}")
    found_subdomains_set = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    yield {"method": "crtsh", "status": "starting", "message": f"Querying crt.sh for {domain}"}

    for attempt in range(CONFIG["max_retries"]):
        try:
            logger.debug(f"Attempt {attempt + 1} to fetch crt.sh data for {domain}")
            # Running requests.get in a thread pool executor
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, # Uses default ThreadPoolExecutor
                lambda: requests.get(url, timeout=CONFIG["http_timeout"] * (attempt + 1))
            )
            response.raise_for_status()
            data = await loop.run_in_executor(None, response.json)
            
            progress_tracker['crtsh']['results_fetched'] = len(data)
            
            potential_subdomains_from_crtsh = set()
            for entry in data:
                name = entry.get('name_value', '').lower().strip()
                if name.endswith("." + domain) or name == domain: # Ensure it's related to the target
                    # Handle multiple names in one entry (separated by newline)
                    for n_part in name.split('\n'):
                        n_clean = n_part.strip().lstrip('*.') # Clean leading wildcards/dots
                        if n_clean and (n_clean.endswith("." + domain) or n_clean == domain):
                             # Avoid adding the bare domain or empty strings if cleaning results in that
                            if n_clean != domain and "." in n_clean:
                                potential_subdomains_from_crtsh.add(n_clean)
            
            progress_tracker['crtsh']['potential'] = len(potential_subdomains_from_crtsh)
            yield {"method": "crtsh", "status": "resolving", 
                   "message": f"Found {len(potential_subdomains_from_crtsh)} potential subdomains from crt.sh. Resolving...",
                   "potential_count": len(potential_subdomains_from_crtsh)}
            logger.debug(f"Retrieved {len(potential_subdomains_from_crtsh)} potential subdomains from crt.sh for {domain}")
            
            if potential_subdomains_from_crtsh:
                tasks = [resolve_subdomain_async(sub, resolver, semaphore) for sub in potential_subdomains_from_crtsh]
                results_for_batch = await asyncio.gather(*tasks, return_exceptions=True)
                
                for sub, res_ips in zip(potential_subdomains_from_crtsh, results_for_batch):
                    if isinstance(res_ips, list) and res_ips:
                        if sub not in found_subdomains_set:
                            found_subdomains_set.add(sub)
                            progress_tracker['crtsh']['confirmed'] += 1
                            logger.debug(f"Confirmed crt.sh subdomain: {sub} -> {res_ips}")
                            yield {"method": "crtsh", "status": "found", "subdomain": sub, "ips": res_ips}
                    elif isinstance(res_ips, Exception):
                        err_msg = f"crt.sh resolution error for {sub} (aiodns): {res_ips}"
                        logger.debug(err_msg) # Debug, as some might not resolve
                        # progress_tracker['crtsh']['errors'].append(err_msg) # Optionally add to errors

            progress_tracker['crtsh']['status'] = 'completed'
            logger.info(f"crt.sh fetching for {domain} completed. Confirmed {len(found_subdomains_set)} subdomains")
            return # Success, exit retry loop
        
        except requests.RequestException as e:
            err_msg = f"crt.sh request failed (attempt {attempt + 1}): {e}"
            progress_tracker['crtsh']['errors'].append(err_msg)
            logger.warning(f"Attempt {attempt + 1} failed for crt.sh ({domain}): {e}")
            yield {"method": "crtsh", "status": "retry", "attempt": attempt + 1, "error": str(e)}
            if attempt < CONFIG["max_retries"] - 1:
                await asyncio.sleep(CONFIG["backoff_factor"] ** attempt)
            else:
                logger.error(f"Failed to fetch crt.sh subdomains for {domain} after {CONFIG['max_retries']} attempts")
                progress_tracker['crtsh']['status'] = 'failed'
                return # Failed all retries
    progress_tracker['crtsh']['status'] = 'failed' # Should be set inside loop if all retries fail


async def enumerate_subdomains(domain: str, brute_force_tier: str = "medium") -> AsyncGenerator[Dict[str, Any], None]:
    logger.info(f"Starting subdomain enumeration for {domain} (streaming progress) with brute_force_tier='{brute_force_tier}'")
    all_confirmed_subdomains = set()
    collected_errors: List[str] = []

    progress_tracker = {
        'brute': {'status': 'pending', 'confirmed': 0, 'errors': [], 'total_to_check':0, 'checked_count':0},
        'search': {'status': 'pending', 'confirmed': 0, 'results_fetched': 0, 'potential': 0, 'errors': []},
        'crtsh': {'status': 'pending', 'confirmed': 0, 'results_fetched': 0, 'potential': 0, 'errors': []},
        'dns': {'status': 'pending', 'confirmed': 0, 'potential': 0, 'errors': []}
    }

    dns_resolver = aiodns.DNSResolver(timeout=CONFIG["dns_timeout"])
    resolve_semaphore = asyncio.Semaphore(CONFIG["resolution_concurrency"])

    yield {"event_type": "enumeration_start", "domain": domain, "message": "Subdomain enumeration process started."}

    # --- Brute Force ---
    progress_tracker['brute']['status'] = 'running'
    loaded_wordlist_for_brute_force = load_wordlist(tier=brute_force_tier)
    async for brute_update in brute_force_subdomains(domain, loaded_wordlist_for_brute_force, progress_tracker, dns_resolver, resolve_semaphore):
        if brute_update.get("status") == "found":
            all_confirmed_subdomains.add(brute_update["subdomain"])
        yield {"event_type": "progress_update", "source": "brute_force", "details": brute_update}
    # Brute-force errors (like timeouts for the whole batch) could be added, but individual resolution failures are not typically "errors" for this method.
    # if progress_tracker['brute']['errors']: collected_errors.extend([f"BruteForce: {e_str}" for e_str in progress_tracker['brute']['errors']])
    yield {"event_type": "method_complete", "source": "brute_force", "confirmed_count": progress_tracker['brute']['confirmed'], "status": progress_tracker['brute']['status']}

    # --- Web Search (SearXNG) ---
    progress_tracker['search']['status'] = 'running'
    yield {"event_type": "progress_update", "source": "web_search", "details": {"status": "running", "message": "Starting SearXNG web search..."}}
    try:
        search_confirmed_list = await get_subdomains_from_search_async(domain, progress_tracker, dns_resolver, resolve_semaphore)
        for sub in search_confirmed_list:
            if sub not in all_confirmed_subdomains:
                all_confirmed_subdomains.add(sub)
                yield {"event_type": "progress_update", "source": "web_search", "details": {"status": "found", "subdomain": sub}}
    except Exception as e:
        logger.error(f"Web search method failed unexpectedly at enumeration level for {domain}: {e}")
        progress_tracker['search']['status'] = 'failed'
        progress_tracker['search']['errors'].append(f"Outer error in web_search: {str(e)}")
    if progress_tracker['search']['errors']: collected_errors.extend([f"WebSearch: {e_str}" for e_str in progress_tracker['search']['errors']])
    yield {"event_type": "method_complete", "source": "web_search", "confirmed_count": progress_tracker['search']['confirmed'], "status": progress_tracker['search']['status']}

    # --- CRTSH ---
    progress_tracker['crtsh']['status'] = 'running'
    async for crtsh_update in fetch_crtsh_subdomains(domain, progress_tracker, dns_resolver, resolve_semaphore):
        if crtsh_update.get("status") == "found":
            all_confirmed_subdomains.add(crtsh_update["subdomain"])
        yield {"event_type": "progress_update", "source": "crtsh", "details": crtsh_update}
    if progress_tracker['crtsh']['errors']: collected_errors.extend([f"CrtSh: {e_str}" for e_str in progress_tracker['crtsh']['errors']])
    yield {"event_type": "method_complete", "source": "crtsh", "confirmed_count": progress_tracker['crtsh']['confirmed'], "status": progress_tracker['crtsh']['status']}

    # --- DNS Query ---
    progress_tracker['dns']['status'] = 'running'
    yield {"event_type": "progress_update", "source": "dns_query", "details": {"status": "running", "message": "Starting DNS queries..."}}
    try:
        dns_confirmed_list = await get_subdomains_from_dns_async(domain, progress_tracker, dns_resolver, resolve_semaphore)
        for sub in dns_confirmed_list:
            if sub not in all_confirmed_subdomains:
                all_confirmed_subdomains.add(sub)
                yield {"event_type": "progress_update", "source": "dns_query", "details": {"status": "found", "subdomain": sub}}
    except Exception as e:
        logger.error(f"DNS query method failed unexpectedly at enumeration level for {domain}: {e}")
        progress_tracker['dns']['status'] = 'failed'
        progress_tracker['dns']['errors'].append(f"Outer error in dns_query: {str(e)}")
    if progress_tracker['dns']['errors']: collected_errors.extend([f"DnsQuery: {e_str}" for e_str in progress_tracker['dns']['errors']])
    yield {"event_type": "method_complete", "source": "dns_query", "confirmed_count": progress_tracker['dns']['confirmed'], "status": progress_tracker['dns']['status']}

    logger.info(f"All enumeration methods for {domain} completed. Total unique subdomains: {len(all_confirmed_subdomains)}")
    
    final_result_data_dict = {
        "target": domain,
        "subdomains": sorted(list(all_confirmed_subdomains)),
        "count": len(all_confirmed_subdomains),
        "timestamp": datetime.utcnow().isoformat() + "Z", # Use UTC
        "errors": collected_errors,
        "status": "completed" # Overall status
    }
    
    try:
        validated_result = SubDomainEnumResult(**final_result_data_dict)
        yield {"__final_result__": True, "data": validated_result.model_dump()}
    except ValidationError as e:
        logger.error(f"Final SubDomainEnumerator result validation failed for {domain}: {e.errors()}")
        # Add validation errors to the collected_errors list for more detail
        for error_detail in e.errors():
            loc_str = ".".join(map(str, error_detail['loc']))
            collected_errors.append(f"ValidationError ({loc_str}): {error_detail['msg']} (value: {error_detail.get('input')})")
        
        final_result_data_dict["errors"] = collected_errors # Update with validation errors
        final_result_data_dict["status"] = "failed_validation"

        yield {"__final_result__": True, "data": {"error": f"Validation failed: {str(e)}", "partial_result": final_result_data_dict}}


def run_enumeration_in_process(domain: str, brute_force_tier: str, result_queue: multiprocessing.Queue):
    logger.debug(f"SubdomainMapper process (PID {os.getpid()}) starting enumeration for {domain} with tier '{brute_force_tier}'")

    def signal_handler(sig, frame):
        logger.warning(f"SubdomainMapper process (PID {os.getpid()}) received signal {sig}. Attempting graceful shutdown.")
        # Try to inform the queue about termination.
        # This might not always get through if the process is killed abruptly.
        try:
            result_queue.put({"__final_result__": True, "data": {"error": f"Process terminated by signal {sig}.", "status": "aborted"}})
        except Exception:
            pass # Queue might be closed or full
        sys.exit(0) # Exit gracefully

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler) # Handle Ctrl+C in the child

    async def main_for_process():
        async for update_or_final_result in enumerate_subdomains(domain, brute_force_tier=brute_force_tier):
            result_queue.put(update_or_final_result)

    try:
        asyncio.run(main_for_process())
        logger.debug(f"SubdomainMapper process (PID {os.getpid()}) for {domain} completed main_for_process.")
    except Exception as e:
        logger.error(f"Unhandled error in SubdomainMapper process (PID {os.getpid()}) for {domain}: {e}", exc_info=True)
        result_queue.put({"__final_result__": True, "data": {"error": f"Process level unhandled error: {str(e)}", "status": "failed"}})
    finally:
        logger.debug(f"SubdomainMapper process (PID {os.getpid()}) for {domain} is finishing.")


async def subDomainMapper4LLM(domain: str, brute_force_tier: str = "medium") -> AsyncGenerator[Dict[str, Any], None]:
    subDomainMapper4LLM._is_streaming_tool = True # type: ignore
    logger.info(f"Initiating subdomain enumeration via subDomainMapper4LLM for {domain} with brute_force_tier='{brute_force_tier}' (streaming)")

    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=run_enumeration_in_process,
        args=(domain, brute_force_tier, result_queue),
    )
    process.start()
    logger.info(f"Started SubdomainMapper process (PID {process.pid}) for {domain}")

    process_completed_normally = False
    while True:
        try:
            item = result_queue.get(timeout=0.5) # Check queue with timeout
            yield item
            if isinstance(item, dict) and item.get("__final_result__"):
                logger.info(f"Received final result marker from process for {domain}. Stopping.")
                process_completed_normally = True
                break
        except multiprocessing.queues.Empty: # Corrected exception type
            if not process.is_alive():
                logger.warning(f"SubdomainMapper process for {domain} (PID {process.pid}) terminated unexpectedly.")
                if not process_completed_normally: # Only yield error if not already handled
                    yield {"__final_result__": True, "data": {"error": "Enumeration process terminated unexpectedly.", "status": "aborted"}}
                break
            await asyncio.sleep(0.1) # Brief pause if queue is empty but process is alive
        except (EOFError, BrokenPipeError) as e: # Handle cases where queue/pipe breaks
            logger.error(f"Queue communication error for {domain} (PID {process.pid}): {e}", exc_info=True)
            if not process_completed_normally:
                 yield {"__final_result__": True, "data": {"error": f"Queue communication error: {str(e)}", "status": "failed"}}
            break
        except Exception as e: # Catch-all for other queue errors
            logger.error(f"Unexpected error reading from SubdomainMapper process queue for {domain}: {e}", exc_info=True)
            if not process_completed_normally:
                yield {"__final_result__": True, "data": {"error": f"Unexpected queue error: {str(e)}", "status": "failed"}}
            break
            
    logger.debug(f"Joining SubdomainMapper process (PID {process.pid}) for {domain}.")
    process.join(timeout=10) # Wait for the process to finish
    if process.is_alive():
        logger.warning(f"SubdomainMapper process (PID {process.pid}) for {domain} did not terminate after join. Terminating forcefully.")
        process.terminate() # Force terminate if still alive
        process.join(timeout=5) # Wait for termination
        if process.is_alive():
            logger.error(f"SubdomainMapper process (PID {process.pid}) for {domain} could not be terminated. Killing.")
            process.kill() # Last resort
            process.join()

    logger.info(f"subDomainMapper4LLM for {domain} finished processing queue and process.")