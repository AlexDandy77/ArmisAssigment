from src.api_clients.base_client import BaseApiClient
from typing import Iterator, Dict, Any, Optional
import os
from dotenv import load_dotenv, dotenv_values
load_dotenv()

class CrowdStrikeApiClient(BaseApiClient):
    API_TOKEN: str = os.getenv("API_TOKEN")
    BASE_URL: str = "https://api.recruiting.app.silk.security"
    ENDPOINT: str = "/api/crowdstrike/hosts/get"
    MAX_API_LIMIT: int = 2
    MAX_API_SKIP: int = 6

    def __init__(self):
        super().__init__()
        print("CrowdstrikeApiClient initialized.")

    def fetch_hosts(self, page_limit: Optional[int] = None, skip: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        print(f"Starting to fetch hosts from CrowdStrike with page_limit={page_limit if page_limit is not None else self.MAX_API_LIMIT}...")
        yield from self.fetch_all_hosts(page_limit=page_limit, skip=skip)
