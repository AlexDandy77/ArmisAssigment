import datetime
from typing import Dict, Any, List
from pymongo.database import Database
from src.models.unified_host import UnifiedHost

class Deduplicator:
    # Rules for matching, each has a field to check and a weight
    DEDUPLICATION_RULES = [
        {"field": "primary_mac_address", "weight": 50, "description": "Primary MAC Address Match"},
        {"field": "cloud_instance_id", "weight": 50, "description": "Cloud Provider Instance ID Match"},
        {"field": "hostname", "weight": 15, "description": "Hostname Match"},
        {"field": "private_ip", "weight": 10, "description": "Primary Private IP Match"},
        {"field": "public_ip", "weight": 10, "description": "Primary Public IP Match"},
    ]

    CONFIDENCE_THRESHOLD = 45

    def __init__(self, db: Database):
        self.collection = db["unified_assets"]
        self._ensure_indexes()

    def _ensure_indexes(self):
        print("Ensuring database indexes exist for deduplication...")
        self.collection.create_index([("primary_mac_address", 1)], sparse=True)
        self.collection.create_index([("cloud_instance_id", 1)], sparse=True)
        self.collection.create_index([("hostname", 1)], sparse=True)
        self.collection.create_index([("private_ip", 1)], sparse=True)
        self.collection.create_index([("public_ip", 1)], sparse=True)

    def _find_candidates(self, host: UnifiedHost) -> List[Dict[str, Any]]:
        # Query to find any document that shares at least one strong identifier
        query_parts = []
        if host.primary_mac_address:
            query_parts.append({"primary_mac_address": host.primary_mac_address})
        if host.cloud_instance_id:
            query_parts.append({"cloud_instance_id": host.cloud_instance_id})
        if host.hostname:
            query_parts.append({"hostname": host.hostname})

        if not query_parts:
            return []

        query = {"$or": query_parts}
        return list(self.collection.find(query))

    def _calculate_match_score(self, new_host: UnifiedHost, existing_doc: Dict[str, Any]) -> int:
        score = 0
        print(f"--- Scoring against existing host ID: {existing_doc['_id']} ---")
        for rule in self.DEDUPLICATION_RULES:
            field = rule["field"]
            new_value = getattr(new_host, field, None)
            existing_value = existing_doc.get(field)

            if new_value is not None and new_value == existing_value:
                print(f"  [+] Match on '{rule['description']}'. Adding {rule['weight']} points.")
                score += rule['weight']
        print(f"--- Total Score: {score} ---")
        return score

    def _merge_hosts(self, incoming_host: UnifiedHost, existing_doc: Dict[str, Any]) -> Dict[str, Any]:
        update_payload = {"$set": {}}
        incoming_id = list(incoming_host.source_ids.keys())[0]

        incoming_source = "Unknown"
        if incoming_id == "qualys_id":
            incoming_source = "Qualys"
        elif incoming_id == "crowdstrike_id":
            incoming_source = "CrowdStrike"
        elif incoming_id == "tenable_id":
            incoming_source = "Tenable"

        # Merge Logic
        for field in ["hostname", "os_name", "os_platform", "kernel_version", "manufacturer", "product_model",
                      "processor_info", "public_ip", "private_ip", "last_boot_timestamp", "default_gateway"]:
            new_val = getattr(incoming_host, field)
            if new_val is not None:
                update_payload["$set"][field] = new_val

        for source, source_id in incoming_host.source_ids.items():
            update_payload["$set"][f"source_ids.{source}"] = source_id

        # Software
        existing_software_raw = existing_doc.get("installed_software", [])
        incoming_software = incoming_host.installed_software or []

        consolidated_software = [s for s in existing_software_raw if incoming_source not in s.get("sources", [])]
        software_lookup = {(s.get("vendor"), s.get("product"), s.get("version")): s for s in consolidated_software}

        for sw in incoming_software:
            key = (sw.vendor, sw.product, sw.version)
            if key in software_lookup:
                software_lookup[key]["sources"].append(incoming_source)
                software_lookup[key]["sources"] = sorted(list(set(software_lookup[key]["sources"])))
            else:
                consolidated_software.append(sw.model_dump(exclude_none=True))

        update_payload["$set"]["installed_software"] = consolidated_software

        # Network interfaces
        existing_interfaces_raw = existing_doc.get("network_interfaces", [])
        incoming_interfaces = incoming_host.network_interfaces or []

        consolidated_interfaces = [i for i in existing_interfaces_raw if incoming_source not in i.get("sources", [])]
        interface_lookup = {i.get("mac_address"): i for i in consolidated_interfaces if i.get("mac_address")}

        for iface in incoming_interfaces:
            mac = iface.mac_address
            if mac and mac in interface_lookup:
                # Interface with this MAC exists, update it
                existing_iface = interface_lookup[mac]
                # Merge sources
                existing_iface["sources"] = sorted(list(set(existing_iface.get("sources", []) + [incoming_source])))
                # Enrich with potentially new IP info
                if iface.private_ip_v4: existing_iface["private_ip_v4"] = iface.private_ip_v4
                if iface.public_ip_v4: existing_iface["public_ip_v4"] = iface.public_ip_v4
                if iface.ip_v6: existing_iface["ip_v6"] = iface.ip_v6
            else:
                consolidated_interfaces.append(iface.model_dump(exclude_none=True))

        update_payload["$set"]["network_interfaces"] = consolidated_interfaces

        # Cloud context
        if incoming_host.cloud_context:
            merged_cloud_context = (existing_doc.get("cloud_context") or {}).copy()
            merged_cloud_context.update(
                {k: v for k, v in incoming_host.cloud_context.model_dump(exclude_none=True).items()})
            update_payload["$set"]["cloud_context"] = merged_cloud_context

        # Merge source-specific security info
        if incoming_host.qualys_security:
            update_payload["$set"]["qualys_security"] = incoming_host.qualys_security.model_dump(exclude_none=True)
        if incoming_host.crowdstrike_security:
            update_payload["$set"]["crowdstrike_security"] = incoming_host.crowdstrike_security.model_dump(exclude_none=True)
        if incoming_host.tenable_security:
            update_payload["$set"]["tenable_security"] = incoming_host.tenable_security.model_dump(exclude_none=True)

        update_payload["$set"]["record_last_updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"

        return update_payload

    def upsert_host(self, host: UnifiedHost):
        candidates = self._find_candidates(host)

        best_match = None
        highest_score = 0

        for candidate_doc in candidates:
            score = self._calculate_match_score(host, candidate_doc)
            if score > highest_score:
                highest_score = score
                best_match = candidate_doc

        if highest_score > self.CONFIDENCE_THRESHOLD:
            print(f"Confident match found (Score: {highest_score}). Merging with host ID: {best_match['_id']}\n")
            update_operation = self._merge_hosts(host, best_match)
            self.collection.update_one({"_id": best_match["_id"]}, update_operation)
        else:
            print("No confident match found. Inserting as new host.\n")
            self.collection.insert_one(host.model_dump())
