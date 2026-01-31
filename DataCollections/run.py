"""
Example script to run the training data import
Place this file in your project root directory (same level as the db/ folder)
"""

from db import TrainingDataDB
import pandas as pd
import logging

# Setup logging to see what's happening
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # Initialize database connection
    print("🔌 Connecting to MongoDB...")
    db = TrainingDataDB()
    
    # Load CSV file
    print("\n📂 Loading CSV file...")
    df = pd.read_csv("training_urls.csv")
    csv_data = df.to_dict('records')
    print(f"   Loaded {len(csv_data)} rows from CSV")
    # Import data
    print("\n📥 Importing data to MongoDB...")
    result = db.bulk_insert_from_csv(csv_data)
    
    # Print results
    print("\n✅ Import Complete!")
    print(f"   Inserted: {result['inserted']}")
    print(f"   Duplicates: {result['duplicates']}")
    print(f"   Errors: {result['errors']}")
    print(f"   Total Processed: {result['total_processed']}")
    
    # Show statistics
    db.print_statistics()
    
    # Close connection
    print("🔌 Closing database connection...")
    db.close()
    print("✅ Done!\n")

if __name__ == "__main__":
    main()