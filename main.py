from src.api_clients.qualys_client import QualysApiClient
from src.api_clients.crowdstrike_client import CrowdStrikeApiClient

def main():
    print("--- Starting Data Fetching Process ---")

    qualys_client = QualysApiClient()

    print("\n--- Fetching from Qualys (using default limit=2) ---")
    qualys_hosts_count_default = 0
    try:
        for host in qualys_client.fetch_hosts():
            if qualys_hosts_count_default < 10:
                print(
                    f"Qualys Host (default limit) Sample: ID={host.get('id', 'N/A')}, Hostname={host.get('name', 'N/A')}")
            qualys_hosts_count_default += 1
    except ValueError as e:
        print(f"Error during Qualys default fetch: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during Qualys default fetch: {e}")
    print(f"--- Finished fetching from Qualys (default limit). Total hosts fetched: {qualys_hosts_count_default} ---")

    print("\n--- Fetching from Qualys (using limit=1) ---")
    qualys_hosts_count_limit_1 = 0
    try:
        for host in qualys_client.fetch_hosts(page_limit=1, skip=0):
            if qualys_hosts_count_limit_1 < 10:
                print(f"Qualys Host (limit=1) Sample: ID={host.get('id', 'N/A')}, Hostname={host.get('name', 'N/A')}")
            qualys_hosts_count_limit_1 += 1
    except ValueError as e:
        print(f"Error during Qualys limit=1 fetch: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during Qualys limit=1 fetch: {e}")
    print(f"--- Finished fetching from Qualys (limit=1). Total hosts fetched: {qualys_hosts_count_limit_1} ---")

    crowdstrike_client = CrowdStrikeApiClient()

    print("\n--- Fetching from CrowdStrike (using default limit=2) ---")
    crowdstrike_hosts_count_default = 0
    try:
        for host in crowdstrike_client.fetch_hosts():
            if crowdstrike_hosts_count_default < 10:
                print(
                    f"CrowdStrike Host (default limit) Sample: ID={host.get('device_id', 'N/A')}, Hostname={host.get('hostname', 'N/A')}")
            crowdstrike_hosts_count_default += 1
    except ValueError as e:
        print(f"Error during CrowdStrike default fetch: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CrowdStrike default fetch: {e}")
    print(
        f"--- Finished fetching from CrowdStrike (default limit). Total hosts fetched: {crowdstrike_hosts_count_default} ---")

    print("\n--- Fetching from CrowdStrike (using limit=1) ---")
    crowdstrike_hosts_count_limit_1 = 0
    try:
        for host in crowdstrike_client.fetch_hosts(page_limit=1, skip=0):
            if crowdstrike_hosts_count_limit_1 < 10:
                print(
                    f"CrowdStrike Host (limit=1) Sample: ID={host.get('device_id', 'N/A')}, Hostname={host.get('hostname', 'N/A')}")
            crowdstrike_hosts_count_limit_1 += 1
    except ValueError as e:
        print(f"Error during CrowdStrike limit=1 fetch: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CrowdStrike limit=1 fetch: {e}")
    print(
        f"--- Finished fetching from CrowdStrike (limit=1). Total hosts fetched: {crowdstrike_hosts_count_limit_1} ---")

    print("\n--- Data Fetching Process Complete ---")

if __name__ == "__main__":
    main()