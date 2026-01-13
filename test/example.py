from pymongo import MongoClient
from datetime import datetime
from typing import Dict, Any, List, Optional

class TrainingDataDB:
    def __init__(self, connection_string=None):
        
        if connection_string is None:
            connection_string = "mongodb://localhost:27017/"
        
        self.client = MongoClient(connection_string)
        self.db = self.client['security_scanner']  
        self.collection = self.db['training_data']  
        
        self.collection.create_index("url", unique=True)
        self.collection.create_index("label")
        self.collection.create_index("scanned")
    
    def insert_url(self, url: str, label: str, source: str = "manual") -> bool:
        
        try:
            doc = {
                "url": url,
                "label": label,  
                "source": source,
                "date_added": datetime.now(),
                "scanned": False,
                "scan_date": None,
                "scan_results": None,
                "features": None
            }
            
            self.collection.insert_one(doc)
            return True
            
        except Exception as e:
            print(f"Error inserting {url}: {e}")
            return False
    
    def bulk_insert_urls(self, urls: List[Dict[str, str]]) -> int:
        
        try:
            documents = []
            
            for url_data in urls:
                doc = {
                    "url": url_data['url'],
                    "label": url_data['label'],
                    "source": url_data.get('source', 'manual'),
                    "date_added": datetime.now(),
                    "scanned": False,
                    "scan_date": None,
                    "scan_results": None,
                    "features": None
                }
                documents.append(doc)
            
            result = self.collection.insert_many(documents, ordered=False)
            return len(result.inserted_ids)
            
        except Exception as e:
            print(f"Bulk insert completed with some duplicates skipped")
            
            return len([d for d in documents if self.collection.find_one({"url": d["url"]})])
    
    def update_scan_results(self, url: str, scan_results: Dict, features: Dict) -> bool:
        try:
            self.collection.update_one(
                {"url": url},
                {
                    "$set": {
                        "scanned": True,
                        "scan_date": datetime.now(),
                        "scan_results": scan_results,
                        "features": features
                    }
                }
            )
            return True
        except Exception as e:
            print(f"Error updating scan results for {url}: {e}")
            return False
    
    def get_unscanned_urls(self, limit: Optional[int] = None) -> List[Dict]:
        
        query = {"scanned": False}
        
        if limit:
            return list(self.collection.find(query).limit(limit))
        else:
            return list(self.collection.find(query))
    
    def get_scanned_urls(self, label: Optional[str] = None) -> List[Dict]:
        query = {"scanned": True}
        
        if label:
            query["label"] = label
        
        return list(self.collection.find(query))
    
    def get_training_dataset(self) -> List[Dict]:
        
        return list(self.collection.find({
            "scanned": True,
            "features": {"$ne": None}
        }))
    
    def get_statistics(self) -> Dict:
        
        total = self.collection.count_documents({})
        scanned = self.collection.count_documents({"scanned": True})
        unscanned = self.collection.count_documents({"scanned": False})
        
        safe_total = self.collection.count_documents({"label": "safe"})
        safe_scanned = self.collection.count_documents({"label": "safe", "scanned": True})
        
        dangerous_total = self.collection.count_documents({"label": "dangerous"})
        dangerous_scanned = self.collection.count_documents({"label": "dangerous", "scanned": True})
        
        return {
            "total_urls": total,
            "scanned": scanned,
            "unscanned": unscanned,
            "safe": {
                "total": safe_total,
                "scanned": safe_scanned,
                "unscanned": safe_total - safe_scanned
            },
            "dangerous": {
                "total": dangerous_total,
                "scanned": dangerous_scanned,
                "unscanned": dangerous_total - dangerous_scanned
            }
        }
    
    def close(self):
        
        self.client.close()



if __name__ == "__main__":
    db = TrainingDataDB()
    
    # Print statistics
    stats = db.get_statistics()
    print("Training Data Statistics:")
    print(f"Total URLs: {stats['total_urls']}")
    print(f"Scanned: {stats['scanned']}")
    print(f"Unscanned: {stats['unscanned']}")
    print(f"\nSafe: {stats['safe']['scanned']}/{stats['safe']['total']}")
    print(f"Dangerous: {stats['dangerous']['scanned']}/{stats['dangerous']['total']}")
    
    db.close()