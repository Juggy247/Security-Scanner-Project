from pymongo import MongoClient, ASCENDING, DESCENDING
from datetime import datetime
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class TrainingDataDB:
    """
    Manages training data in MongoDB for AI/ML model training.
    Handles URL import, text extraction tracking, and embedding storage.
    """
    
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        """
        Initialize connection to MongoDB training data collection.
        
        Args:
            connection_string: MongoDB connection string
        """
        try:
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            
            self.db = self.client["security_scanner"]
            self.collection = self.db["training_data"]
            
            # Create indexes for efficient queries
            self._create_indexes()
            
            logger.info("✅ TrainingDataDB connected successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            raise
    
    def _create_indexes(self):
        """Create indexes for efficient querying"""
        # Unique index on URL
        self.collection.create_index("url", unique=True)
        
        # Indexes for filtering
        self.collection.create_index("label")
        self.collection.create_index([("text_extracted", ASCENDING)])
        self.collection.create_index([("embedding_generated", ASCENDING)])
        self.collection.create_index([("date_added", DESCENDING)])
        
        # Compound index for common queries
        self.collection.create_index([
            ("text_extracted", ASCENDING),
            ("label", ASCENDING)
        ])
    
    # ==================== IMPORT METHODS ====================
    
    def insert_url(self, url: str, label: str, source: str, date_collected: str = None) -> bool:
        """
        Insert a single URL into training data.
        
        Args:
            url: The URL to add
            label: 'safe' or 'dangerous'
            source: Source of the URL (e.g., 'tranco', 'phishtank')
            date_collected: When the URL was collected (optional)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            doc = {
                "url": url,
                "label": label,
                "source": source,
                "date_collected": date_collected or datetime.now().isoformat(),
                "date_added": datetime.now(),
                
                # Text extraction status
                "text_extracted": False,
                "text_extraction_date": None,
                "text_data": None,
                
                # Embedding generation status
                "embedding_generated": False,
                "embedding_generation_date": None,
                "embedding_data": None,
                
                # Scan results (added later)
                "scan_results": None,
                "scan_date": None,
                
                # Processing status
                "processing_errors": [],
                "last_updated": datetime.now()
            }
            
            self.collection.insert_one(doc)
            return True
            
        except Exception as e:
            logger.error(f"Error inserting URL {url}: {e}")
            return False
    
    def bulk_insert_from_csv(self, csv_data: List[Dict[str, str]]) -> Dict[str, int]:
        """
        Bulk insert URLs from CSV data.
        
        Args:
            csv_data: List of dicts with keys: url, label, source, date_collected
        
        Returns:
            Dictionary with counts of inserted, duplicates, and errors
        """
        inserted = 0
        duplicates = 0
        errors = 0
        
        for item in csv_data:
            try:
                doc = {
                    "url": item["url"],
                    "label": item["label"],
                    "source": item.get("source", "unknown"),
                    "date_collected": item.get("date_collected", datetime.now().isoformat()),
                    "date_added": datetime.now(),
                    
                    # Processing status
                    "text_extracted": False,
                    "text_extraction_date": None,
                    "text_data": None,
                    
                    "embedding_generated": False,
                    "embedding_generation_date": None,
                    "embedding_data": None,
                    
                    "scan_results": None,
                    "scan_date": None,
                    
                    "processing_errors": [],
                    "last_updated": datetime.now()
                }
                
                self.collection.insert_one(doc)
                inserted += 1
                
            except Exception as e:
                if "duplicate key error" in str(e).lower():
                    duplicates += 1
                else:
                    errors += 1
                    logger.error(f"Error inserting {item.get('url', 'unknown')}: {e}")
        
        return {
            "inserted": inserted,
            "duplicates": duplicates,
            "errors": errors,
            "total_processed": len(csv_data)
        }
    
    # ==================== TEXT EXTRACTION METHODS ====================
    
    def update_text_extraction(self, url: str, text_data: Dict[str, Any], 
                               scan_results: Dict[str, Any] = None) -> bool:
        """
        Update URL with extracted text data.
        
        Args:
            url: The URL to update
            text_data: Dictionary containing extracted text (title, description, etc.)
            scan_results: Optional security scan results
        
        Returns:
            True if successful
        """
        try:
            update_doc = {
                "text_extracted": True,
                "text_extraction_date": datetime.now(),
                "text_data": text_data,
                "last_updated": datetime.now()
            }
            
            if scan_results:
                update_doc["scan_results"] = scan_results
                update_doc["scan_date"] = datetime.now()
            
            result = self.collection.update_one(
                {"url": url},
                {"$set": update_doc}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Error updating text for {url}: {e}")
            return False
    
    def mark_text_extraction_failed(self, url: str, error: str) -> bool:
        """
        Mark URL as failed during text extraction.
        
        Args:
            url: The URL that failed
            error: Error message
        
        Returns:
            True if successful
        """
        try:
            self.collection.update_one(
                {"url": url},
                {
                    "$set": {
                        "text_extracted": False,
                        "text_extraction_date": datetime.now(),
                        "last_updated": datetime.now()
                    },
                    "$push": {
                        "processing_errors": {
                            "stage": "text_extraction",
                            "error": error,
                            "timestamp": datetime.now()
                        }
                    }
                }
            )
            return True
            
        except Exception as e:
            logger.error(f"Error marking failure for {url}: {e}")
            return False
    
    # ==================== EMBEDDING METHODS ====================
    
    def update_embedding(self, url: str, embedding: List[float], 
                        model_name: str, embedding_dimension: int) -> bool:
        """
        Update URL with generated embedding.
        
        Args:
            url: The URL to update
            embedding: The embedding vector (list of floats)
            model_name: Name of the SBERT model used
            embedding_dimension: Dimension of the embedding (e.g., 384)
        
        Returns:
            True if successful
        """
        try:
            embedding_data = {
                "embedding": embedding,
                "model": model_name,
                "dimension": embedding_dimension,
                "generation_date": datetime.now().isoformat()
            }
            
            self.collection.update_one(
                {"url": url},
                {
                    "$set": {
                        "embedding_generated": True,
                        "embedding_generation_date": datetime.now(),
                        "embedding_data": embedding_data,
                        "last_updated": datetime.now()
                    }
                }
            )
            return True
            
        except Exception as e:
            logger.error(f"Error updating embedding for {url}: {e}")
            return False
    
    # ==================== QUERY METHODS ====================
    
    def get_urls_needing_text_extraction(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get URLs that haven't had text extracted yet.
        
        Args:
            limit: Maximum number of URLs to return (None = all)
        
        Returns:
            List of URL documents
        """
        query = {"text_extracted": False}
        
        cursor = self.collection.find(query)
        if limit:
            cursor = cursor.limit(limit)
        
        return list(cursor)
    
    def get_urls_with_text(self, label: Optional[str] = None, limit: Optional[int] = None) -> List[Dict]:
        """
        Get URLs that have text extracted.
        
        Args:
            label: Filter by label ('safe' or 'dangerous'), None = all
            limit: Maximum number to return
        
        Returns:
            List of URL documents with text data
        """
        query = {"text_extracted": True}
        
        if label:
            query["label"] = label
        
        cursor = self.collection.find(query)
        if limit:
            cursor = cursor.limit(limit)
        
        return list(cursor)
    
    def get_urls_needing_embeddings(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get URLs that have text but no embeddings yet.
        
        Args:
            limit: Maximum number to return
        
        Returns:
            List of URL documents
        """
        query = {
            "text_extracted": True,
            "embedding_generated": False
        }
        
        cursor = self.collection.find(query)
        if limit:
            cursor = cursor.limit(limit)
        
        return list(cursor)
    
    def get_all_embeddings(self, label: Optional[str] = None) -> List[Dict]:
        """
        Get all URLs with embeddings (for training).
        
        Args:
            label: Filter by label ('safe' or 'dangerous'), None = all
        
        Returns:
            List of URL documents with embeddings
        """
        query = {"embedding_generated": True}
        
        if label:
            query["label"] = label
        
        return list(self.collection.find(query))
    
    def get_url_by_url(self, url: str) -> Optional[Dict]:
        """
        Get a specific URL document.
        
        Args:
            url: The URL to find
        
        Returns:
            URL document or None
        """
        return self.collection.find_one({"url": url})
    
    # ==================== STATISTICS METHODS ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the training data.
        
        Returns:
            Dictionary with counts and status
        """
        total = self.collection.count_documents({})
        
        # By label
        safe_count = self.collection.count_documents({"label": "safe"})
        dangerous_count = self.collection.count_documents({"label": "dangerous"})
        
        # Text extraction status
        text_extracted = self.collection.count_documents({"text_extracted": True})
        text_pending = self.collection.count_documents({"text_extracted": False})
        
        # Embedding status
        embeddings_generated = self.collection.count_documents({"embedding_generated": True})
        embeddings_pending = self.collection.count_documents({
            "text_extracted": True,
            "embedding_generated": False
        })
        
        # Ready for training (has both text and embedding)
        ready_for_training = self.collection.count_documents({
            "text_extracted": True,
            "embedding_generated": True
        })
        
        return {
            "total_urls": total,
            "by_label": {
                "safe": safe_count,
                "dangerous": dangerous_count
            },
            "text_extraction": {
                "completed": text_extracted,
                "pending": text_pending,
                "percentage": round((text_extracted / total * 100) if total > 0 else 0, 1)
            },
            "embeddings": {
                "generated": embeddings_generated,
                "pending": embeddings_pending,
                "percentage": round((embeddings_generated / total * 100) if total > 0 else 0, 1)
            },
            "training_ready": {
                "count": ready_for_training,
                "percentage": round((ready_for_training / total * 100) if total > 0 else 0, 1)
            }
        }
    
    def print_statistics(self):
        """Print formatted statistics"""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("📊 TRAINING DATA STATISTICS")
        print("="*60)
        
        print(f"\n📁 Total URLs: {stats['total_urls']}")
        print(f"   ├─ Safe: {stats['by_label']['safe']}")
        print(f"   └─ Dangerous: {stats['by_label']['dangerous']}")
        
        print(f"\n📝 Text Extraction:")
        print(f"   ├─ Completed: {stats['text_extraction']['completed']} ({stats['text_extraction']['percentage']}%)")
        print(f"   └─ Pending: {stats['text_extraction']['pending']}")
        
        print(f"\n🧮 Embeddings:")
        print(f"   ├─ Generated: {stats['embeddings']['generated']} ({stats['embeddings']['percentage']}%)")
        print(f"   └─ Pending: {stats['embeddings']['pending']}")
        
        print(f"\n✅ Ready for Training: {stats['training_ready']['count']} ({stats['training_ready']['percentage']}%)")
        print("="*60 + "\n")
    
    # ==================== UTILITY METHODS ====================
    
    def close(self):
        """Close MongoDB connection"""
        self.client.close()
        logger.info("MongoDB connection closed")


# Example usage and testing
if __name__ == "__main__":
    import pandas as pd
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    db = TrainingDataDB()
    
    # Example: Import from CSV
    print("📥 Importing from CSV...")
    df = pd.read_csv("training_urls.csv")
    csv_data = df.to_dict('records')
    
    result = db.bulk_insert_from_csv(csv_data)
    print(f"✅ Import complete:")
    print(f"   Inserted: {result['inserted']}")
    print(f"   Duplicates: {result['duplicates']}")
    print(f"   Errors: {result['errors']}")
    
    # Show statistics
    db.print_statistics()
    
    # Close connection
    db.close()