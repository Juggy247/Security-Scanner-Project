from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class TextExtractionMixin:
    """Mixin class for text extraction tracking"""
    
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
                        "text_extracted": "failed",
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