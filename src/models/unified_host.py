from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class NetworkInterface(BaseModel):
    """Represents a single network interface on the host."""
    mac_address: Optional[str] = None
    private_ip_v4: Optional[str] = None
    public_ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class CloudContext(BaseModel):
    """Contains information specific to the cloud provider environment."""
    provider: Optional[str] = None
    account_id: Optional[str] = None
    instance_id: Optional[str] = None
    instance_type: Optional[str] = None
    region: Optional[str] = None
    availability_zone: Optional[str] = None
    image_id: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None


class QualysSecurityInfo(BaseModel):
    """Holds security-related data sourced specifically from Qualys."""
    agent_version: Optional[str] = None
    last_checked_in: Optional[str] = None
    last_vuln_scan: Optional[str] = None
    vulnerability_qids: List[int] = Field(default_factory=list)
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)


class CrowdStrikeSecurityInfo(BaseModel):
    """Holds security-related data sourced specifically from CrowdStrike."""
    agent_version: Optional[str] = None
    status: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    policies: Dict[str, str] = Field(default_factory=dict)


class Software(BaseModel):
    """Represents a single piece of installed software."""
    vendor: Optional[str] = None
    product: str
    version: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class UnifiedHost(BaseModel):
    """A unified model representing a single host, consolidating data from multiple sources."""
    # --- Primary Identifiers for Deduplication ---
    # Strong, reliable identifiers used for further records matching.
    primary_mac_address: Optional[str] = None
    cloud_instance_id: Optional[str] = None

    # --- Source-Specific Identifiers for Traceability ---
    source_ids: Dict[str, str] = Field(default_factory=dict)  # {"qualys_id": "...", "crowdstrike_id": "..."}

    # --- Core Host Information ---
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_platform: Optional[str] = None
    kernel_version: Optional[str] = None
    last_boot_timestamp: Optional[str] = None

    # --- Hardware Information ---
    manufacturer: Optional[str] = None
    product_model: Optional[str] = None
    processor_info: Optional[str] = None
    total_memory_mb: Optional[int] = None

    # --- Network Information ---
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    default_gateway: Optional[str] = None
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)

    # --- Contextual & Security Information ---
    cloud_context: Optional[CloudContext] = None
    qualys_security: Optional[QualysSecurityInfo] = None
    crowdstrike_security: Optional[CrowdStrikeSecurityInfo] = None

    # --- Inventories ---
    installed_software: List[Software] = Field(default_factory=list)

    # --- Metadata ---
    record_created_at: Optional[str] = None
    record_last_updated_at: Optional[str] = None
