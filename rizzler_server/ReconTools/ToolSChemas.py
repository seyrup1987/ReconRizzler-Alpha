# ToolSChemas.py

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime # Ensure datetime is imported

class ReconResult(BaseModel):
    """Base class for reconnaissance results"""
    target: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: str = Field(default="completed")
    model_config = {"arbitrary_types_allowed": True, "extra": "ignore"}

class ScriptOutput(BaseModel):
    """Output of a single script/check run against a port."""
    script_name: str
    output: Dict[str, Any] # Structured output from the script
    summary: Optional[str] = None # Brief human-readable summary
    error: Optional[str] = None
    model_config = {"extra": "allow"}

class OSFingerprintDetail(BaseModel):
    """Detailed OS fingerprinting information."""
    os_family: Optional[str] = None # e.g., Linux, Windows, Cisco
    os_generation: Optional[str] = None # e.g., 2.6.x, 10, 15.x
    device_type: Optional[str] = None # e.g., general purpose, router, switch, printer
    cpe: Optional[str] = None # Common Platform Enumeration
    accuracy: float = Field(default=0.0, description="Confidence score for this specific OS match, if multiple are guessed.")
    raw_fingerprint_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw data points collected for OS fingerprinting")
    model_config = {"extra": "allow"}

class VulnerabilityHint(BaseModel):
    """Information about a potential vulnerability."""
    source_type: str = Field(description="e.g., 'banner_version_match', 'script_finding'")
    description: str
    reference_id: Optional[str] = None # e.g., CVE-ID if applicable, or internal ID
    severity_guess: Optional[str] = Field(default="informational", description="e.g., informational, low, medium, high, critical")
    model_config = {"extra": "allow"}

class PortInfo(BaseModel):
    """Detailed information for a single port."""
    port: int
    protocol: str = Field(default="tcp") # tcp or udp
    state: str = Field(default="open") # open, closed, filtered
    service_name: Optional[str] = None
    version: Optional[str] = None
    
    # Enhanced OS Fingerprinting (can be per port if OS detection varies, or aggregated at top level)
    # For now, let's keep a primary OS guess here, and allow more detailed at top level if needed.
    os_guess: Optional[str] = None # Primary OS guess string (e.g., "Linux 2.6.32 - 3.10")
    os_confidence: Optional[float] = None # Overall confidence for the primary os_guess
    # os_details: Optional[OSFingerprintDetail] = None # More structured OS info, might be better at PortScanResult level

    banner: Optional[str] = None
    headers: Optional[Dict[str, str]] = None # For HTTP/S
    cdn_detected: Optional[str] = None
    web_technology: Optional[str] = None
    web_tech_version: Optional[str] = None
    ssl_info: Optional[Dict[str, Any]] = None # For SSL/TLS details
    
    script_results: List[ScriptOutput] = Field(default_factory=list, description="Results from various enumeration/check scripts")
    potential_vulnerabilities: List[VulnerabilityHint] = Field(default_factory=list, description="Hints of potential vulnerabilities")
    
    error_message: Optional[str] = None
    model_config = {"extra": "allow"}

class HopInfo(BaseModel):
    """Information about a single hop in a traceroute."""
    ttl: int
    ip_address: Optional[str] = None
    host_name: Optional[str] = None
    rtt_ms: Optional[float] = None

class PortScanConfig(BaseModel):
    """Configuration used for the port scan operation."""
    port_range_option: str = Field(default="top-1000", description="e.g., 'top-1000', 'top-100', '1-65535', 'custom'")
    custom_ports: Optional[List[int]] = Field(default=None, description="List of custom ports if port_range_option is 'custom'")
    scan_timeout: float
    stealth_mode: bool
    os_detection_enabled: bool
    service_fingerprinting_enabled: bool
    script_engine_enabled: bool
    # Add other relevant config options here

class PortScanResult(ReconResult):
    """Results of a port scan operation, including TCP, UDP, and other analyses."""
    ip_address: Optional[str] = None
    scan_config: Optional[PortScanConfig] = None # Store the configuration used for this scan
    port_details: List[PortInfo] = Field(default_factory=list, description="Detailed information for scanned ports (TCP and UDP)")
    
    # Aggregated OS detection results if a consistent OS is detected across multiple ports/probes
    # This can be populated after analyzing all PortInfo.os_details
    aggregated_os_fingerprint: Optional[OSFingerprintDetail] = None
    
    traceroute: Optional[List[HopInfo]] = Field(default_factory=list, description="Traceroute path to the target")
    errors: List[str] = Field(default_factory=list, description="Overall errors during the scan (e.g., DNS resolution failure before port scanning starts)")


class SubDomainEnumResult(ReconResult):
    subdomains: List[str] = Field(default_factory=list)
    count: int = Field(default=0)
    errors: List[str] = Field(default_factory=list)

class DnsRecordCollection(BaseModel):
    dns_records: Dict[str, Any] = Field(default_factory=dict, description="Standard DNS records like A, MX, TXT, etc., and CNAME resolutions which can be nested dictionaries.")
    zone_transfer_results: List[Dict[str, Any]] = Field(default_factory=list, description="Results of zone transfer attempts from NS servers.")
    spf_dmarc_analysis: Dict[str, Any] = Field(default_factory=dict, description="Analysis of SPF and DMARC records.")
    model_config = {"extra": "allow"}

class DnsEnumResult(ReconResult):
    records: DnsRecordCollection = Field(default_factory=DnsRecordCollection)
    errors: List[str] = Field(default_factory=list, description="List of errors encountered during enumeration stages.")