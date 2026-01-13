from datetime import datetime
from typing import List
import logging

logger = logging.getLogger(__name__)


class EmbeddingsMixin:
    """Mixin class for embedding tracking"""
    
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