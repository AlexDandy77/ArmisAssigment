from pymongo.database import Database
from src.models.unified_host import UnifiedHost

class Deduplicator:
    def __init__(self, db: Database):
        self.collection = db["unified_assets"]

    def upsert_host(self, host: UnifiedHost):
        pass