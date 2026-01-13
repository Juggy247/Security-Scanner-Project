from datetime import datetime
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class IngestionMixin:
    """Mixin class for data ingestion methods"""
    
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
            error_str = str(e)
            if "duplicate" in error_str.lower() or "11000" in error_str:
                duplicates += 1
            else:
                errors += 1
    
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