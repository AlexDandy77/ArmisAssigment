import requests
import time
from typing import Iterator, Dict, Any, List, Optional

class EndOfDataError(Exception):
    """Custom exception to signal that the API returned an 'end of data' error."""
    pass

class BaseApiClient:
    # values to be overwritten by child classes
    API_TOKEN: str = ""
    BASE_URL: str = ""
    ENDPOINT: str = ""
    MAX_API_LIMIT: int = 1
    MAX_API_SKIP: int = 5

    END_OF_DATA_ERROR_MESSAGE: str = "Error invalid skip/limit combo (>number of hosts)"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "accept": "application/json",
            "token": self.API_TOKEN,
            "Content-Type": "application/json"
        })

    # Fetch a batch of hosts (using skip and limit)
    def _fetch_page(self, skip: int, limit: int) -> List[Dict[str, Any]]:
        url = f"{self.BASE_URL}{self.ENDPOINT}"
        params = {"skip": skip, "limit": limit}

        if not (1 <= limit <= self.MAX_API_LIMIT):
            raise ValueError(f"Invalid limit parameter: {limit}. Must be between 1 and {self.MAX_API_LIMIT}.")

        if skip > self.MAX_API_SKIP:
             print(f"Warning: Attempting to fetch with skip={skip} which is beyond the documented MAX_API_SKIP ({self.MAX_API_SKIP}).")

        try:
            response = self.session.post(url, params=params, data={}, timeout=30)
            response.raise_for_status()

            response_json = response.json()

            if isinstance(response_json, dict) and response_json.get("error"):
                error_details = response_json["error"]
                if isinstance(error_details, list):
                    for err in error_details:
                        error_code = err.get("code", "")
                        error_message = err.get("message", "")
                        print(f"API Error Response: Code={error_code}, Message={error_message}, Details={err}")
                        if "too_big" in error_code and "maximum" in err:
                            raise ValueError(f"API returned 'limit too big' error: Max limit is {err['maximum']}.")
                        elif "Number must be less than or equal to" in error_message:
                            raise ValueError(f"API returned parameter validation error: {error_message}.")
                print(f"API Error: {response_json.get('error')}")
                raise ValueError(f"API returned a general error: {response_json}")

            if isinstance(response_json, list):
                return response_json
            else:
                print(f"Unexpected API response structure for {url}: {response_json}")
                return []

        except requests.exceptions.HTTPError as e:
            if e.response is not None and self.END_OF_DATA_ERROR_MESSAGE in e.response.text:
                print(f"Detected specific end of data error for {self.__class__.__name__} at skip={skip}, limit={limit}.")
                raise EndOfDataError(f"API indicated end of data: {e.response.text}")
            else:
                print(f"HTTP Error fetching data from {url} (skip={skip}, limit={limit}): {e}")
                print(f"Response content: {e.response.text}")
                raise
        except requests.exceptions.ConnectionError as e:
            print(f"Connection Error fetching data from {url} (skip={skip}, limit={limit}): {e}")
            raise
        except requests.exceptions.Timeout as e:
            print(f"Timeout Error fetching data from {url} (skip={skip}, limit={limit}): {e}")
            raise
        except ValueError as e:
            print(f"API Constraint Violation: {e}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"An unexpected requests error occurred while fetching data from {url}: {e}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred while processing response from {url}: {e}")
            raise

    # Main generator function
    def fetch_all_hosts(self, page_limit: Optional[int] = None, skip: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        actual_limit = page_limit if page_limit is not None else self.MAX_API_LIMIT
        if not (1 <= actual_limit <= self.MAX_API_LIMIT):
            raise ValueError(
                f"Requested page_limit ({page_limit}) is invalid. "
                f"Must be between 1 and {self.MAX_API_LIMIT} (inclusive)."
            )

        skip = skip if skip is not None else 0
        while True:
            if skip > self.MAX_API_SKIP:
                print(f"Reached documented maximum allowed skip ({self.MAX_API_SKIP}). Stopping data fetching for {self.__class__.__name__}.")
                break

            hosts_batch = []
            retried_successfully = False
            try:
                print(f"Fetching {self.__class__.__name__} hosts: skip={skip}, limit={actual_limit}")
                hosts_batch = self._fetch_page(skip, actual_limit)

            except EndOfDataError:
                print(f"API returned EndOfDataError with skip={skip}, limit={actual_limit}. Attempting to retry with smaller limits.")
                for retry_limit in range(actual_limit - 1, 0, -1):
                    try:
                        print(f"Retrying with skip={skip}, limit={retry_limit}")
                        hosts_batch = self._fetch_page(skip, retry_limit)
                        if hosts_batch:
                            for host in hosts_batch:
                                yield host
                            retried_successfully = True
                            break
                    except (EndOfDataError, ValueError, requests.exceptions.RequestException) as retry_e:
                        print(f"Retry with skip={skip}, limit={retry_limit} failed: {retry_e}")
                if retried_successfully:
                    break
                else:
                    print(f"No valid smaller limit found for skip={skip}. Stopping data fetching.")
                    break

            except ValueError as e:
                print(f"Stopping {self.__class__.__name__} host fetching due to API constraint: {e}")
                break
            except Exception as e:
                print(f"An unexpected error occurred during {self.__class__.__name__} host fetching loop: {e}")
                break

            if retried_successfully:
                continue

            if not hosts_batch:
                break

            for host in hosts_batch:
                yield host

            skip += actual_limit
            time.sleep(0.05)
