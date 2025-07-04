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
        incoming_source = list(incoming_host.source_ids.keys())[0]

        # Merge Logic
        for field in ["hostname", "os_name", "os_platform", "kernel_version", "manufacturer", "product_model",
                      "processor_info"]:
            new_val = getattr(incoming_host, field)
            if new_val is not None:
                update_payload["$set"][field] = new_val

        if incoming_host.last_boot_timestamp:
            update_payload["$set"]["last_boot_timestamp"] = incoming_host.last_boot_timestamp

        if incoming_host.default_gateway:
            update_payload["$set"]["default_gateway"] = incoming_host.default_gateway

        # Network interfaces
        if incoming_source == 'Qualys': # Replacing whole list
            if incoming_host.network_interfaces is not None:
                update_payload["$set"]["network_interfaces"] = [iface.model_dump(exclude_none=True) for iface in
                                                                incoming_host.network_interfaces]

        elif incoming_source == 'CrowdStrike': # Enriching the list only with new interfaces.
            if incoming_host.network_interfaces:
                existing_interfaces = existing_doc.get("network_interfaces", [])
                existing_keys = {(iface.get("mac_address"), iface.get("private_ip_v4")) for iface in
                                 existing_interfaces}

                interfaces_to_add = []
                for new_iface in incoming_host.network_interfaces:
                    new_key = (new_iface.mac_address, new_iface.private_ip_v4)
                    if new_key not in existing_keys:
                        interfaces_to_add.append(new_iface.model_dump(exclude_none=True))

                if interfaces_to_add:
                    update_payload.setdefault("$addToSet", {})["network_interfaces"] = {"$each": interfaces_to_add}

        # Merge source-specific security info
        if incoming_host.qualys_security:
            update_payload["$set"]["qualys_security"] = incoming_host.qualys_security.model_dump()
        if incoming_host.crowdstrike_security:
            update_payload["$set"]["crowdstrike_security"] = incoming_host.crowdstrike_security.model_dump()

        # Merge source IDs
        for source, source_id in incoming_host.source_ids.items():
            update_payload["$set"][f"source_ids.{source}"] = source_id

        update_payload["$set"]["record_last_updated_at"] = datetime.datetime.now(datetime.UTC).isoformat() + "Z"

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
            print(f"Confident match found (Score: {highest_score}). Merging with host ID: {best_match['_id']}")
            update_operation = self._merge_hosts(host, best_match)
            self.collection.update_one({"_id": best_match["_id"]}, update_operation)
        else:
            print("No confident match found. Inserting as new host.")
            self.collection.insert_one(host.model_dump())
