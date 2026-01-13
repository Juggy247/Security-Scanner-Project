from typing import List, Dict, Optional


class QueriesMixin:
    """Mixin class for database queries"""
    
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