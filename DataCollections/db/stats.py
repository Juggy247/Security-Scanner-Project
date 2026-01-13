from typing import Dict, Any


class StatsMixin:
    """Mixin class for statistics and reporting"""
    
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