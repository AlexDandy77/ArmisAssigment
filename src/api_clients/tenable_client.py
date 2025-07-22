import requests

from src.api_clients.base_client import BaseApiClient
from typing import Iterator, Dict, Any, Optional, List
import os
from dotenv import load_dotenv, dotenv_values
load_dotenv()

class TenableApiClient(BaseApiClient):
    API_TOKEN: str = os.getenv("API_TOKEN")
    BASE_URL: str = "https://api.recruiting.app.silk.security"
    ENDPOINT: str = "/api/tenable/hosts/get"
    CURSOR: str = ''

    def __init__(self):
        super().__init__()
        print("TenableApiClient initialized.")

    def fetch_hosts(self) -> Iterator[Dict[str, Any]]:
        print(f"Starting to fetch hosts from Tenable")
        yield from self.fetch_all_hosts()

    def fetch_all_hosts(self) -> Iterator[Dict[str, Any]]:
        while True:
            hosts_batch = []
            try:
                print(f"Fetching {self.__class__.__name__} hosts, cursor: {self.CURSOR}")
                hosts_batch = self._fetch_page(cursor=self.CURSOR)

            except ValueError as e:
                print(f"Stopping {self.__class__.__name__} host fetching due to API constraint: {e}")
                break
            except Exception as e:
                print(f"An unexpected error occurred during {self.__class__.__name__} host fetching loop: {e}")
                break

            if not hosts_batch:
                break

            for host in hosts_batch:
                yield host


    def _fetch_page(self, cursor: str) -> List[Dict[str, Any]]:
        url = f"{self.BASE_URL}{self.ENDPOINT}"
        params = {"cursor": self.CURSOR}

        try:
            response = self.session.post(url, params=params, data={}, timeout=30)
            response.raise_for_status()

            response_json = response.json()
            hosts = response_json.get("hosts")
            self.CURSOR = response_json.get("cursor")

            if isinstance(hosts, list):
                return hosts
            else:
                print(f"Unexpected API response structure for {url}: {response_json}")
                return []

        except requests.exceptions.ConnectionError as e:
            print(f"Connection Error fetching data from {url}: {e}")
            raise
        except requests.exceptions.Timeout as e:
            print(f"Timeout Error fetching data from {url}: {e}")
            raise
        except ValueError as e:
            print(f"API Constraint Violation: {e}")
            raise
        except requests.exceptions.RequestException as e:
            if e.response.text == 'Invalid cursor':
                print(f"Wrong cursor: {self.CURSOR} on {url}: {e}")
                return []
            raise
        except Exception as e:
            print(f"An unexpected error occurred while processing response from {url}: {e}")
            raise