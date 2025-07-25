import datetime
from typing import Dict, Any, Optional, List

from src.models.unified_host import (
    UnifiedHost,
    NetworkInterface,
    CloudContext,
    QualysSecurityInfo,
    CrowdStrikeSecurityInfo,
    Software
)

class HostNormalizer:
    def normalize_host(self, raw_host: Dict[str, Any], source: str) -> Optional[UnifiedHost]:
        if source == "Qualys":
            return self._normalize_qualys_host(raw_host)
        elif source == "CrowdStrike":
            return self._normalize_crowdstrike_host(raw_host)
        elif source == "Tenable":
            return self._normalize_tenable_host(raw_host)
        else:
            print(f"Warning: No normalizer available for source: {source}")
            return None

    def _normalize_tenable_host(self, raw_host: Dict[str, Any]) -> Optional[UnifiedHost]:
        if not raw_host:
            return None

        # --- Assemble the UnifiedHost object ---
        now = datetime.datetime.utcnow().isoformat() + "Z"
        unified_host = UnifiedHost(
            primary_mac_address=raw_host.get('display_mac_address'),
            cloud_instance_id=raw_host.get('aws_ec2_instance_id'),
            source_ids={"tenable_id": raw_host.get('id')},
            hostname=raw_host.get('host_name'),
            os_name=None,
            os_platform=None,
            kernel_version=None,
            public_ip=raw_host.get('display_ipv4_address'),
            private_ip=None,
            cloud_context=None,
            tenable_security=None,
            installed_software=None,
            network_interfaces=None,
            record_created_at=now,
            record_last_updated_at=now
        )
        return unified_host


    def _normalize_qualys_host(self, raw_host: Dict[str, Any]) -> Optional[UnifiedHost]:
        if not raw_host:
            return None

        # --- Helper functions for safe data extraction ---
        def _safe_get_list(data: Dict, key: str) -> List:
            return data.get(key, {}).get('list', [])

        def _get_aws_ec2_info(sources: List) -> Dict:
            for source in sources:
                if 'Ec2AssetSourceSimple' in source:
                    return source.get('Ec2AssetSourceSimple', {})
            return {}

        # --- Data Extraction ---
        agent_info = raw_host.get('agentInfo', {})
        ec2_info = _get_aws_ec2_info(_safe_get_list(raw_host, 'sourceInfo'))

        primary_mac = None
        interfaces_list = _safe_get_list(raw_host, 'networkInterface')
        if interfaces_list:
            for iface_data in interfaces_list:
                iface = iface_data.get('HostAssetInterface', {})
                if iface.get('macAddress'):
                    primary_mac = iface.get('macAddress')
                    break

        # --- Network Interfaces ---
        grouped_interfaces = {}
        default_gateway = None
        public_ip_from_list = None

        for iface_data in interfaces_list:
            iface = iface_data.get('HostAssetInterface', {})
            mac = iface.get('macAddress')
            address = iface.get('address')

            if not mac and address and '.' in address:
                # This is likely the public IP entry
                public_ip_from_list = address
                continue

            if not mac:
                continue

            if mac not in grouped_interfaces:
                grouped_interfaces[mac] = {
                    "mac_address": mac,
                    "private_ip_v4": None,
                    "public_ip_v4": None,
                    "ip_v6": None,
                    "sources": ['Qualys']
                }

            if iface.get('gatewayAddress'):
                default_gateway = iface.get('gatewayAddress')

            if address:
                if ':' in address:  # IPv6
                    grouped_interfaces[mac]['ip_v6'] = address
                elif address.startswith(('10.', '172.', '192.168.')):  # Private IPv4
                    grouped_interfaces[mac]['private_ip_v4'] = address
                else:  # Assumed Public IPv4
                    grouped_interfaces[mac]['public_ip_v4'] = address

        # Assign the standalone public IP to the primary interface if it wasn't already found
        if public_ip_from_list and primary_mac and primary_mac in grouped_interfaces:
            if not grouped_interfaces[primary_mac]['public_ip_v4']:
                grouped_interfaces[primary_mac]['public_ip_v4'] = public_ip_from_list

        network_interfaces = [NetworkInterface(**data) for data in grouped_interfaces.values()]

        # --- Security Info ---
        qualys_security = QualysSecurityInfo(
            agent_version=agent_info.get('agentVersion'),
            last_checked_in=agent_info.get('lastCheckedIn', {}).get('$date'),
            last_vuln_scan=raw_host.get('lastVulnScan', {}).get('$date'),
            vulnerability_qids=[
                vuln.get('HostAssetVuln', {}).get('qid')
                for vuln in _safe_get_list(raw_host, 'vuln')
                if vuln.get('HostAssetVuln', {}).get('qid')
            ],
            open_ports=[
                {
                    "port": port.get('HostAssetOpenPort', {}).get('port'),
                    "protocol": port.get('HostAssetOpenPort', {}).get('protocol')
                }
                for port in _safe_get_list(raw_host, 'openPort')
            ]
        )

        # --- Software Inventory ---
        installed_software = [
            Software(
                product=sw.get('HostAssetSoftware', {}).get('name'),
                version=sw.get('HostAssetSoftware', {}).get('version'),
                sources=['Qualys']
            )
            for sw in _safe_get_list(raw_host, 'software')
            if sw.get('HostAssetSoftware', {}).get('name')
        ]

        # --- Cloud Context ---
        cloud_context = CloudContext(
            provider=raw_host.get('cloudProvider'),
            account_id=ec2_info.get('accountId'),
            instance_id=ec2_info.get('instanceId'),
            instance_type=ec2_info.get('instanceType'),
            region=ec2_info.get('region'),
            availability_zone=ec2_info.get('availabilityZone'),
            image_id=ec2_info.get('imageId'),
            vpc_id=ec2_info.get('vpcId'),
            subnet_id=ec2_info.get('subnetId'),
        ) if ec2_info else None

        # --- Assemble the UnifiedHost object ---
        now = datetime.datetime.utcnow().isoformat() + "Z"
        unified_host = UnifiedHost(
            primary_mac_address=primary_mac,
            cloud_instance_id=ec2_info.get('instanceId'),
            source_ids={"qualys_id": str(raw_host.get('id'))},
            hostname=raw_host.get('name'),
            os_name=raw_host.get('os'),
            os_platform=agent_info.get('platform'),
            last_boot_timestamp=raw_host.get('lastSystemBoot'),
            manufacturer=raw_host.get('manufacturer'),
            product_model=raw_host.get('model'),
            processor_info=_safe_get_list(raw_host, 'processor')[0].get('HostAssetProcessor', {}).get(
                'name') if _safe_get_list(raw_host, 'processor') else None,
            total_memory_mb=raw_host.get('totalMemory'),
            public_ip=ec2_info.get('publicIpAddress'),
            private_ip=raw_host.get('address'),
            default_gateway=default_gateway,
            network_interfaces=network_interfaces,
            cloud_context=cloud_context,
            qualys_security=qualys_security,
            installed_software=installed_software,
            record_created_at=now,
            record_last_updated_at=now
        )
        return unified_host


    def _normalize_crowdstrike_host(self, raw_host: Dict[str, Any]) -> Optional[UnifiedHost]:
        if not raw_host:
            return None

        # --- Security Info ---
        device_policies = raw_host.get('device_policies', {})
        policies = {
            ptype: policy.get('policy_id')
            for ptype, policy in device_policies.items()
            if policy.get('policy_id')
        }

        crowdstrike_security = CrowdStrikeSecurityInfo(
            agent_version=raw_host.get('agent_version'),
            status=raw_host.get('status'),
            first_seen=raw_host.get('first_seen'),
            last_seen=raw_host.get('last_seen'),
            policies=policies
        )

        # --- Cloud Context ---
        cloud_context = CloudContext(
            provider="AWS" if raw_host.get('service_provider') == 'AWS_EC2_V2' else raw_host.get('service_provider'),
            account_id=raw_host.get('service_provider_account_id'),
            instance_id=raw_host.get('instance_id'),
            availability_zone=raw_host.get('zone_group')
        ) if raw_host.get('service_provider') else None

        # --- Assemble the UnifiedHost object ---
        now = datetime.datetime.utcnow().isoformat() + "Z"
        unified_host = UnifiedHost(
            primary_mac_address=raw_host.get('mac_address', '').replace('-', ':'),
            cloud_instance_id=raw_host.get('instance_id'),
            source_ids={"crowdstrike_id": raw_host.get('device_id')},
            hostname=raw_host.get('hostname'),
            os_name=raw_host.get('os_version'),
            os_platform=raw_host.get('platform_name'),
            kernel_version=raw_host.get('kernel_version'),
            last_boot_timestamp=None,
            manufacturer=raw_host.get('system_manufacturer'),
            product_model=raw_host.get('system_product_name'),
            processor_info=None,
            total_memory_mb=None,
            public_ip=raw_host.get('external_ip'),
            private_ip=raw_host.get('local_ip'),
            default_gateway=raw_host.get('default_gateway_ip'),
            network_interfaces=[
                NetworkInterface(mac_address=raw_host.get('mac_address', '').replace('-', ':'),
                                 private_ip_v4=raw_host.get('local_ip', ''),
                                 sources=['CrowdStrike'])
            ],
            cloud_context=cloud_context,
            crowdstrike_security=crowdstrike_security,
            record_created_at=now,
            record_last_updated_at=now
        )
        return unified_host
