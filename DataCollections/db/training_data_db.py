from .connection import MongoDBConnection
from .ingestion import IngestionMixin
from .text_extraction import TextExtractionMixin
from .embeddings import EmbeddingsMixin
from .queries import QueriesMixin
from .stats import StatsMixin


class TrainingDataDB(
    MongoDBConnection,
    IngestionMixin,
    TextExtractionMixin,
    EmbeddingsMixin,
    QueriesMixin,
    StatsMixin
):
    """
    Manages training data in MongoDB for AI/ML model training.
    Handles URL import, text extraction tracking, and embedding storage.
    
    This class combines all functionality through multiple inheritance:
    - MongoDBConnection: Connection management and indexing
    - IngestionMixin: Data import methods
    - TextExtractionMixin: Text extraction tracking
    - EmbeddingsMixin: Embedding generation tracking
    - QueriesMixin: Query methods
    - StatsMixin: Statistics and reporting
    """
    
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        """
        Initialize connection to MongoDB training data collection.
        
        Args:
            connection_string: MongoDB connection string
        """
        # Initialize the connection (calls MongoDBConnection.__init__)
        super().__init__(connection_string)


# Example usage and testing
if __name__ == "__main__":
    import pandas as pd
    import logging
    
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