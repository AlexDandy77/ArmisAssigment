import os
from pymongo import MongoClient
from src.api_clients.crowdstrike_client import CrowdStrikeApiClient
from src.api_clients.qualys_client import QualysApiClient
from src.normalization.host_normalizer import HostNormalizer
from src.deduplication.deduplicator import Deduplicator

def process_source(client, source, deduplicator):
    print(f"\n--- Processing source: {source} ---")
    host_normalizer = HostNormalizer()
    count = 0
    for raw_host in client.fetch_hosts():
        normalized_host = host_normalizer.normalize_host(raw_host, source)
        if normalized_host:
            deduplicator.upsert_host(normalized_host)
            count += 1
    print(f"--- Finished {source}. Processed {count} hosts. ---")

def main():
    db_pass: str = os.getenv("DB_PASSWORD")
    mongo_client = MongoClient(f"mongodb+srv://AlexDandy77:{db_pass}@main.0umme3r.mongodb.net/?retryWrites=true&w=majority&appName=main")

    try:
        mongo_client.admin.command('ping')
        print("Successfully connected to MongoDB!")
    except Exception as e:
        print(e)

    db = mongo_client["asset_inventory"]

    deduplicator = Deduplicator(db)

    qualys_client = QualysApiClient()
    crowdstrike_client = CrowdStrikeApiClient()

    print("\n--- Starting the Pipeline. ---")
    process_source(qualys_client, "Qualys", deduplicator)
    process_source(crowdstrike_client, "CrowdStrike", deduplicator)
    print("\n--- Pipeline Complete. Data has been fetched, normalized, and merged in MongoDB. ---")

if __name__ == "__main__":
    main()