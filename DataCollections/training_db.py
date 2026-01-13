from pymongo import MongoClient
from datetime import datetime
from typing import List, Dict


class TrainingDataDB:
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        self.client = MongoClient(connection_string)
        self.db = self.client["security_scanner"]
        self.collection = self.db["training_data"]

       
        self.collection.create_index("url", unique=True)

    def insert_url(self, url: str, label: str, source: str) -> bool:
        
        try:
            self.collection.insert_one({
                "url": url,
                "label": label,
                "source": source,
                "date_added": datetime.now()
            })
            return True
        except Exception:
            
            return False

    def bulk_insert(self, urls: List[Dict[str, str]]) -> int:
        
        documents = []

        for item in urls:
            documents.append({
                "url": item["url"],
                "label": item["label"],
                "source": item["source"],
                "date_added": datetime.now()
            })

        try:
            result = self.collection.insert_many(documents, ordered=False)
            return len(result.inserted_ids)
        except Exception:
            
            return self.collection.count_documents({})

    def close(self):
        self.client.close()
