# In ReconTools/PortParser.py

import os
import socket as st
import ssl
import asyncio
import aiohttp
import logging
import dns.resolver
from typing import Dict, List, Optional, Any, AsyncGenerator
from collections import defaultdict
import re
import json
import argparse
import random
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from pydantic import ValidationError
from ReconTools.ToolSChemas import PortScanResult, PortInfo, HopInfo, PortScanConfig, OSFingerprintDetail, VulnerabilityHint, ScriptOutput
import nmap # Import the python-nmap library
import ipaddress
from datetime import datetime
import xml.etree.ElementTree as ET

# --- Logging Setup ---
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# --- Configuration ---
DEFAULT_PORTS = list(range(1, 1025))  # Common ports
SCAN_TIMEOUT = 2.0 # This will be used as max-rtt-timeout for Nmap probes
CONCURRENT_SCANS = 100 # This is less relevant with consolidated Nmap
STEALTH_MODE = True # Influences Nmap scan type
PRIVILEGED = True # Assume privileged execution for more scan types
NMAP_OS_DETECTION = True # Enable OS detection via nmap
NMAP_VERSION_DETECTION = True # Enable version detection via nmap
SCRIPT_ENGINE_ENABLED = True # Enable script engine

# --- File Paths (These are not directly used by python-nmap's scan method for --versiondb/--osdb) ---
# NMAP_SERVICE_PROBES_FILE = os.path.join(os.path.dirname(__file__), '..', 'config', 'nmap-service-probes.txt')
# NMAP_OS_DB_FILE = os.path.join(os.path.dirname(__file__), '..', 'config', 'nmap-os-db.txt')

# --- Helper Functions ---
def is_valid_ipv4_address(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

async def resolve_hostname(hostname):
    try:
        # Use getaddrinfo for more robust resolution, including IPv6 if needed
        # For now, sticking to gethostbyname for IPv4 consistency with original
        return await asyncio.get_event_loop().run_in_executor(None, st.gethostbyname, hostname)
    except st.gaierror:
        return None

def check_privileges() -> bool:
    """Checks if the current process has root/administrator privileges."""
    if os.name == 'posix':
        return os.geteuid() == 0
    elif os.name == 'nt': # Windows
        try:
            # Attempt to open a privileged registry key
            import win32security
            win32security.OpenProcessToken(win32security.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
            return True
        except Exception:
            return False
    return False

# --- Deprecate or remove these as Nmap will handle the core scanning ---
# async def tcp_connect_scan(...)
# async def syn_scan(...)
# async def udp_scan(...)
# async def scan_port(...)
# async def fingerprint_service(...)
# async def detect_os(...)

async def run_script(host: str, port: int) -> Optional[ScriptOutput]:
    """Runs a custom script against a port (example)."""
    try:
        # Replace this with your actual script execution logic
        if port == 80 or port == 443: # Check common HTTP/S ports
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{host}:{port}/robots.txt"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=5) as response:
                        if response.status == 200:
                            content = await response.text()
                            return ScriptOutput(script_name="robots_txt_check", output={"robots_txt": content, "url": url}, summary=f"robots.txt found at {url}")
                        else:
                            return ScriptOutput(script_name="robots_txt_check", output={"status": response.status, "url": url}, summary=f"robots.txt not found or inaccessible at {url}")
            except aiohttp.ClientError as e:
                return ScriptOutput(script_name="robots_txt_check", output={"error": str(e), "url": url}, error=f"HTTP client error: {e}")
            except Exception as e:
                return ScriptOutput(script_name="robots_txt_check", output={"error": str(e), "url": url}, error=f"Unexpected error during robots.txt check: {e}")
        return None  # No script to run for this port

    except Exception as e:
        logger.error(f"Error running script on {host}:{port}: {e}")
        return ScriptOutput(script_name="unknown", output={"error": str(e)}, error=str(e))

async def scan_host_with_nmap(
    host: str,
    ports: List[int],
    scan_type: str = "tcp",
    os_detection_enabled: bool = NMAP_OS_DETECTION,
    service_fingerprinting_enabled: bool = NMAP_VERSION_DETECTION,
    script_engine_enabled: bool = SCRIPT_ENGINE_ENABLED,
    scan_timeout: float = SCAN_TIMEOUT,
    stealth_mode: bool = STEALTH_MODE
) -> tuple[List[PortInfo], Optional[OSFingerprintDetail], List[str]]:
    """
    Performs a comprehensive Nmap scan for port states, service versions, and OS detection.
    Parses the Nmap XML output to populate PortInfo and OSFingerprintDetail.
    """
    nm = nmap.PortScanner()
    logger.info(f"Starting comprehensive Nmap scan for {host} on {len(ports)} ports.")

    nmap_args = []
    errors = []

    # Determine scan type based on user preference and privileges
    if scan_type == "syn" and check_privileges():
        nmap_args.append("-sS") # SYN scan (requires root)
        logger.debug("Using SYN scan (-sS).")
    elif scan_type == "udp":
        nmap_args.append("-sU") # UDP scan
        logger.debug("Using UDP scan (-sU).")
    else:
        nmap_args.append("-sT") # TCP connect scan (default, no root needed)
        logger.debug("Using TCP connect scan (-sT).")

    # Add service version detection
    if service_fingerprinting_enabled:
        nmap_args.append("-sV")
        nmap_args.append("--version-intensity 5") # More aggressive version detection
        logger.debug("Service version detection enabled (-sV).")

    # Add OS detection
    if os_detection_enabled:
        nmap_args.append("-O")
        logger.debug("OS detection enabled (-O).")

    # Add timing and timeout options
    # -T4 (aggressive) is a good balance for speed without being too noisy
    nmap_args.append("-T4")
    # Max RTT timeout for individual probes, helps with slow hosts
    nmap_args.append(f"--max-rtt-timeout {int(scan_timeout * 1000)}ms")
    # Host timeout for the entire scan of a single host
    # A heuristic: 2 seconds per port, minimum 30s, maximum 300s
    host_timeout_s = max(30, min(300, int(scan_timeout * len(ports))))
    nmap_args.append(f"--host-timeout {host_timeout_s}s")
    logger.debug(f"Nmap host timeout set to {host_timeout_s}s.")

    # Convert port list to Nmap format
    ports_str = ",".join(map(str, ports))

    full_nmap_arguments_str = " ".join(nmap_args)
    logger.debug(f"Nmap arguments: {full_nmap_arguments_str}")

    port_details: List[PortInfo] = []
    aggregated_os_fingerprint: Optional[OSFingerprintDetail] = None

    try:
        # Execute Nmap scan in a separate thread to avoid blocking the event loop
        await asyncio.to_thread(nm.scan, host, ports_str, arguments=full_nmap_arguments_str)

        if host not in nm.all_hosts():
            error_msg = f"Nmap scan did not find host {host} or host is down."
            errors.append(error_msg)
            logger.warning(error_msg)
            return [], None, errors

        host_data = nm[host]

        # Process OS detection results
        if os_detection_enabled and 'osmatch' in host_data and host_data['osmatch']:
            best_match = host_data['osmatch'][0]
            os_name = best_match['name']
            os_accuracy = float(best_match['accuracy'])

            os_family = None
            os_generation = None
            device_type = None
            cpe = None

            if 'osclass' in best_match and best_match['osclass']:
                os_class = best_match['osclass'][0]
                os_family = os_class.get('osfamily')
                os_generation = os_class.get('osgen')
                device_type = os_class.get('type')
                
                # Fix: Ensure cpe is a string
                raw_cpe = os_class.get('cpe')
                if isinstance(raw_cpe, list) and raw_cpe:
                    cpe = raw_cpe[0] # Take the first CPE string
                elif isinstance(raw_cpe, str):
                    cpe = raw_cpe
                else:
                    cpe = None

            aggregated_os_fingerprint = OSFingerprintDetail(
                os_family=os_family,
                os_generation=os_generation,
                device_type=device_type,
                cpe=cpe,
                accuracy=os_accuracy,
                # Fix: Pass the best_match dictionary itself for raw_fingerprint_data
                raw_fingerprint_data=best_match 
            )
            logger.info(f"OS detected for {host}: {os_name} (Accuracy: {os_accuracy}%)")

        # Prepare tasks for concurrent script execution
        script_tasks = []
        ports_to_process = [] # Temporary list to hold PortInfo objects before script results are added

        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                port_data = host_data[proto][port]
                state = port_data.get('state', 'unknown')
                service_name = port_data.get('name')
                version = port_data.get('version')
                product = port_data.get('product')
                extrainfo = port_data.get('extrainfo')
                banner = f"{service_name or ''} {product or ''} {version or ''} {extrainfo or ''}".strip()

                port_info = PortInfo(
                    port=port,
                    protocol=proto,
                    state=state,
                    service_name=service_name,
                    version=version,
                    banner=banner,
                    os_guess=aggregated_os_fingerprint.os_family if aggregated_os_fingerprint else None,
                    os_confidence=aggregated_os_fingerprint.accuracy if aggregated_os_fingerprint else None
                )
                ports_to_process.append(port_info)

                # Add script task if enabled and port is open
                if script_engine_enabled and state == 'open':
                    script_tasks.append(run_script(host, port))
                else:
                    script_tasks.append(None) # Placeholder for non-scripted ports to maintain index alignment

        # Execute all script tasks concurrently
        if script_tasks:
            # Filter out None tasks before gathering, then map results back
            active_script_tasks = [task for task in script_tasks if task is not None]
            script_results = await asyncio.gather(*active_script_tasks, return_exceptions=True)
            
            # Map results back to their respective PortInfo objects
            script_result_idx = 0
            for i, port_info in enumerate(ports_to_process):
                # Only process if a script was intended for this port
                if script_engine_enabled and port_info.state == 'open':
                    result = script_results[script_result_idx]
                    if isinstance(result, Exception):
                        logger.warning(f"Error running script on {host}:{port_info.port} (custom script): {result}")
                        port_info.error_message = f"Script error: {result}"
                    elif result:
                        port_info.script_results.append(result)
                    script_result_idx += 1
        
        port_details = ports_to_process # Update the main list with script results

        logger.info(f"Nmap scan completed for {host}. Found {len(port_details)} ports.")
        return port_details, aggregated_os_fingerprint, errors

    except nmap.PortScannerError as e:
        error_msg = f"Nmap scan failed for {host}: {e}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)
        return [], None, errors
    except Exception as e:
        error_msg = f"Unexpected error during Nmap scan for {host}: {e}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)
        return [], None, errors

async def port_scanner_async_generator(domain: str, ports: List[int], scan_type: str,
                                        os_detection_enabled: bool,
                                        service_fingerprinting_enabled: bool,
                                        script_engine_enabled: bool,
                                        scan_timeout: float,
                                        stealth_mode: bool) -> AsyncGenerator[Dict[str, Any], None]:
    """Asynchronous port scanner, yielding progress."""
    try:
        if is_valid_ipv4_address(domain):
            target_ip = domain
        elif is_valid_hostname(domain):
            target_ip = await resolve_hostname(domain)
            if not target_ip:
                yield {"type": "error", "target": domain, "message": "Could not resolve hostname."}
                yield {"__final_result__": True, "data": {"error": "Could not resolve hostname."}}
                return
        else:
            yield {"type": "error", "target": domain, "message": "Invalid domain or IP address."}
            yield {"__final_result__": True, "data": {"error": "Invalid domain or IP address."}}
            return

        yield {"type": "scan_start", "target": domain, "ip_address": target_ip, "message": f"Starting {scan_type.upper()} scan on {domain} ({target_ip})"}

        # Use the new consolidated Nmap scan function
        port_details, aggregated_os_fingerprint, scan_errors = await scan_host_with_nmap(
            target_ip, ports, scan_type,
            os_detection_enabled, service_fingerprinting_enabled, script_engine_enabled,
            scan_timeout, stealth_mode
        )

        # Convert PortInfo objects to dictionaries for JSON serialization
        scan_results_dicts = [p.model_dump() for p in port_details]

        yield {"type": "scan_complete", "target": domain, "ip_address": target_ip, "open_ports": scan_results_dicts, "message": f"{scan_type.upper()} scan completed."}

        # Determine port_range_option for PortScanConfig
        port_range_option_str = "custom"
        if ports == list(range(1, 2001)): # Updated to match the default in main.py
            port_range_option_str = "top-2000" 
        elif ports == list(range(1, 1025)): # Original default
            port_range_option_str = "top-1024"

        final_tool_output = {
            "target": domain,
            "ip_address": target_ip,
            "port_details": scan_results_dicts,
            "aggregated_os_fingerprint": aggregated_os_fingerprint.model_dump() if aggregated_os_fingerprint else None,
            "errors": scan_errors,
            "timestamp": datetime.utcnow().isoformat() + "Z", # Add timestamp as per ReconResult base
            "status": "completed" # Add status as per ReconResult base
        }
        
        # Validate against PortScanResult schema before yielding final result
        try:
            PortScanResult(**final_tool_output)
            yield {"__final_result__": True, "data": final_tool_output}
        except ValidationError as e:
            logger.error(f"Validation error for PortScanResult: {e.errors()}")
            # If validation fails, still send an error message in the final result
            yield {"__final_result__": True, "data": {"error": f"Validation error in final result: {e.errors()}", "raw_data": final_tool_output}}


    except Exception as e:
        logger.error(f"Error in port_scanner_async_generator for {domain}: {e}", exc_info=True)
        yield {"type": "error", "target": domain, "message": f"Scan failed: {e}"}
        yield {"__final_result__": True, "data": {"error": str(e)}}

async def run_scanner_generator(domain: str, ports: List[int] = DEFAULT_PORTS, scan_type: str = "tcp",
                                os_detection_enabled: bool = NMAP_OS_DETECTION,
                                service_fingerprinting_enabled: bool = NMAP_VERSION_DETECTION,
                                script_engine_enabled: bool = SCRIPT_ENGINE_ENABLED,
                                scan_timeout: float = SCAN_TIMEOUT,
                                stealth_mode: bool = STEALTH_MODE) -> AsyncGenerator[Dict[str, Any], None]:
    """Tool wrapper for the port scanner."""
    async for item in port_scanner_async_generator(domain, ports, scan_type,
                                                    os_detection_enabled, service_fingerprinting_enabled,
                                                    script_engine_enabled, scan_timeout, stealth_mode):
        yield item

async def portScanner4LLM(domain: str, ports: List[int] = DEFAULT_PORTS, scan_type: str = "tcp",
                            os_detection_enabled: bool = NMAP_OS_DETECTION,
                            service_fingerprinting_enabled: bool = NMAP_VERSION_DETECTION,
                            script_engine_enabled: bool = SCRIPT_ENGINE_ENABLED,
                            scan_timeout: float = SCAN_TIMEOUT,
                            stealth_mode: bool = STEALTH_MODE) -> AsyncGenerator[Dict[str, Any], None]:
    """Port scanner for LLM integration."""
    portScanner4LLM._is_streaming_tool = True  # type: ignore
    async for item in run_scanner_generator(domain, ports, scan_type,
                                            os_detection_enabled, service_fingerprinting_enabled,
                                            script_engine_enabled, scan_timeout, stealth_mode):
        yield item