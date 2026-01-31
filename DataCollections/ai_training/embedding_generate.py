"""
SBERT Embedding Generator
Converts extracted text into semantic embeddings for KNN classification.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Dict
import time
from datetime import datetime

from db.training_data_db import TrainingDataDB


class EmbeddingGenerator:
    """
    Generates SBERT embeddings for training data.
    
    Uses sentence-transformers library to convert text into
    384-dimensional semantic vectors.
    """
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize embedding generator.
        
        Args:
            model_name: SBERT model to use
                - 'all-MiniLM-L6-v2': Fast, 384 dims (recommended)
                - 'all-mpnet-base-v2': Slower, 768 dims (more accurate)
        """
        print(f"🤖 Loading SBERT model: {model_name}")
        print("   (This may take a minute on first run...)")
        
        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
        self.embedding_dimension = self.model.get_sentence_embedding_dimension()
        
        print(f"✅ Model loaded!")
        print(f"   Embedding dimension: {self.embedding_dimension}")
        
        self.db = TrainingDataDB()
    
    def generate_embedding(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Text to embed
        
        Returns:
            Numpy array of embedding values
        """
        # Encode text to embedding
        embedding = self.model.encode(text, show_progress_bar=False)
        return embedding
    
    def generate_batch_embeddings(self, texts: List[str], batch_size: int = 32) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts efficiently.
        
        Args:
            texts: List of texts to embed
            batch_size: Batch size for encoding
        
        Returns:
            List of embedding arrays
        """
        print(f"   Encoding {len(texts)} texts in batches of {batch_size}...")
        
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        
        return embeddings
    
    def process_single_url(self, url_doc: Dict) -> bool:
        """
        Generate and store embedding for a single URL.
        
        Args:
            url_doc: URL document from MongoDB with text_data
        
        Returns:
            True if successful
        """
        url = url_doc['url']
        text_data = url_doc.get('text_data', {})
        
        # Get combined text
        combined_text = text_data.get('combined_text', '')
        
        if not combined_text or len(combined_text) < 20:
            print(f"   ⚠️  Skipping {url}: insufficient text")
            return False
        
        try:
            # Generate embedding
            embedding = self.generate_embedding(combined_text)
            
            # Convert to list for MongoDB storage
            embedding_list = embedding.tolist()
            
            # Store in database
            success = self.db.update_embedding(
                url=url,
                embedding=embedding_list,
                model_name=self.model_name,
                embedding_dimension=self.embedding_dimension
            )
            
            return success
            
        except Exception as e:
            print(f"   ❌ Error generating embedding for {url}: {e}")
            return False
    
    def process_all_batch(self, batch_size: int = 50) -> Dict[str, int]:
        """
        Process all URLs needing embeddings in batches.
        
        Args:
            batch_size: Number of URLs to process at once
        
        Returns:
            Statistics about processing
        """
        print("\n" + "="*60)
        print("🧮 GENERATING EMBEDDINGS")
        print("="*60)
        
        # Show initial stats
        self.db.print_statistics()
        
        # Get URLs needing embeddings
        urls_to_process = self.db.get_urls_needing_embeddings()
        
        if not urls_to_process:
            print("\n✅ No URLs need embeddings!")
            return {"processed": 0, "successful": 0, "failed": 0}
        
        print(f"\n📊 Found {len(urls_to_process)} URLs needing embeddings")
        
        total_successful = 0
        total_failed = 0
        
        # Process in batches
        for i in range(0, len(urls_to_process), batch_size):
            batch = urls_to_process[i:i+batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(urls_to_process) + batch_size - 1) // batch_size
            
            print(f"\n📦 Batch {batch_num}/{total_batches} ({len(batch)} URLs)")
            print("="*60)
            
            # Extract texts from batch
            texts = []
            urls = []
            valid_docs = []
            
            for doc in batch:
                text_data = doc.get('text_data', {})
                combined_text = text_data.get('combined_text', '')
                
                if combined_text and len(combined_text) >= 20:
                    texts.append(combined_text)
                    urls.append(doc['url'])
                    valid_docs.append(doc)
                else:
                    total_failed += 1
            
            if not texts:
                print("   ⚠️  No valid texts in this batch")
                continue
            
            print(f"   Valid URLs in batch: {len(texts)}")
            
            # Generate embeddings for entire batch
            try:
                embeddings = self.generate_batch_embeddings(texts, batch_size=32)
                
                # Store each embedding
                print(f"\n   💾 Storing embeddings...")
                for j, (url, embedding) in enumerate(zip(urls, embeddings)):
                    embedding_list = embedding.tolist()
                    
                    success = self.db.update_embedding(
                        url=url,
                        embedding=embedding_list,
                        model_name=self.model_name,
                        embedding_dimension=self.embedding_dimension
                    )
                    
                    if success:
                        total_successful += 1
                    else:
                        total_failed += 1
                    
                    # Show progress every 10 URLs
                    if (j + 1) % 10 == 0:
                        print(f"   Stored: {j+1}/{len(texts)}")
                
                print(f"   ✅ Batch complete: {len(texts)} embeddings stored")
                
            except Exception as e:
                print(f"   ❌ Batch failed: {e}")
                total_failed += len(texts)
        
        # Final statistics
        print("\n" + "="*60)
        print("✅ EMBEDDING GENERATION COMPLETE")
        print("="*60)
        print(f"\n📊 Results:")
        print(f"   Successful: {total_successful}")
        print(f"   Failed: {total_failed}")
        
        if total_successful + total_failed > 0:
            success_rate = (total_successful / (total_successful + total_failed)) * 100
            print(f"   Success Rate: {success_rate:.1f}%")
        
        # Show updated stats
        self.db.print_statistics()
        
        return {
            "processed": len(urls_to_process),
            "successful": total_successful,
            "failed": total_failed
        }
    
    def close(self):
        """Clean up resources"""
        self.db.close()
        print("👋 Embedding generator closed")


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SBERT Embedding Generator')
    parser.add_argument('--model', default='all-MiniLM-L6-v2',
                       help='SBERT model to use')
    parser.add_argument('--batch-size', type=int, default=50,
                       help='Batch size for processing')
    
    args = parser.parse_args()
    
    generator = EmbeddingGenerator(model_name=args.model)
    
    try:
        generator.process_all_batch(batch_size=args.batch_size)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user. Progress saved in database.")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        generator.close()