from pymongo import MongoClient, ASCENDING, DESCENDING
import logging

logger = logging.getLogger(__name__)


class MongoDBConnection:
    """Handles MongoDB connection and index creation"""
    
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        """
        Initialize connection to MongoDB.
        
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
            
            logger.info("✅ MongoDB connected successfully")
            
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
    
    def close(self):
        """Close MongoDB connection"""
        self.client.close()
        logger.info("MongoDB connection closed")