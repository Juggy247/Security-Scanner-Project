"""
Training Data Processing Pipeline
Handles the complete workflow from CSV import to text extraction.
"""

import sys
import time
from typing import Dict, List, Optional
from datetime import datetime
import pandas as pd
import requests
import urllib3

# Disable SSL warnings for phishing sites
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from your organized structure
from db.training_data_db import TrainingDataDB
from ai_training.text_processor import TextProcessor


class TrainingPipeline:
    

    def __init__(self):
        
        print(" Training Pipeline Start...")
        self.db = TrainingDataDB()
        self.text_processor = TextProcessor()
        
        # Create session for HTTP requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        print(" Pipeline Started\n")
    
    def fetch_url(self, url: str, timeout: int = 15) -> Optional[requests.Response]:
        """
        Args:
            url: URL to fetch
            timeout: Request timeout in seconds
        """
        try:
            response = self.session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False  # Allow invalid SSL for phishing sites
            )
            return response
        except requests.exceptions.Timeout:
            print(f"             Timeout")
            return None
        except requests.exceptions.ConnectionError:
            print(f"             Connection error")
            return None
        except Exception as e:
            print(f"            Error: {str(e)[:50]}")
            return None
    
    def import_csv(self, csv_path: str) -> Dict[str, int]:
        
        print("\n" + "-"*60)
        print(" IMPORTING CSV TO MONGODB")
        print("-"*60)
        
        try:
            # Load CSV
            print(f"\n📂 Loading: {csv_path}")
            df = pd.read_csv(csv_path)
            
            print(f" Found {len(df)} URLs in CSV")
            print(f"   Safe: {len(df[df['label'] == 'safe'])}")
            print(f"   Dangerous: {len(df[df['label'] == 'dangerous'])}")
            
            
            csv_data = df.to_dict('records')
            
            
            print(f"\n Importing to MongoDB...")
            result = self.db.bulk_insert_from_csv(csv_data)
            
            print(f"\n Import Complete:")
            print(f"   Inserted: {result['inserted']}")
            print(f"   Duplicates (skipped): {result['duplicates']}")
            print(f"   Errors: {result['errors']}")
            
            return result
            
        except FileNotFoundError:
            print(f" Error: File not found: {csv_path}")
            return {"inserted": 0, "duplicates": 0, "errors": 1}
        
        except Exception as e:
            print(f" Error importing CSV: {e}")
            return {"inserted": 0, "duplicates": 0, "errors": 1}
    
    def process_single_url(self, url_doc: Dict) -> bool:
        
        url = url_doc['url']
        
        try:
            # Fetch the page
            response = self.fetch_url(url, timeout=15)
            
            if not response:
                self.db.mark_text_extraction_failed(url, "Dead/unreachable (timeout or connection error)")
                return False
                
            
            if response.status_code != 200:
                error_msg = f"HTTP {response.status_code}"
                self.db.mark_text_extraction_failed(url, error_msg)
                return False
            
            # Extract text
            text_data = self.text_processor.extract_from_response(response, url)
            
            # Check if extraction succeeded
            if not text_data.get('success'):
                error_msg = text_data.get('error', 'Unknown extraction error')
                self.db.mark_text_extraction_failed(url, error_msg)
                return False
            
            # Validate text quality
            if not self.text_processor.validate_text_data(text_data):
                self.db.mark_text_extraction_failed(url, "Insufficient text content")
                return False
            
            # Store in database
            success = self.db.update_text_extraction(url, text_data)
            
            return success
            
        except Exception as e:
            error_msg = str(e)[:100]
            self.db.mark_text_extraction_failed(url, error_msg)
            return False
    
    def process_batch(self, batch_size: int = 50, delay: float = 2.0) -> Dict[str, int]:
        
        # Get URLs that need processing
        urls_to_process = self.db.get_urls_needing_text_extraction(limit=batch_size)
        
        if not urls_to_process:
            print("\n No URLs need processing!")
            return {"processed": 0, "successful": 0, "failed": 0}
        
        print(f"\n🔄 Processing {len(urls_to_process)} URLs...")
        
        successful = 0
        failed = 0
        
        for i, url_doc in enumerate(urls_to_process, 1):
            url = url_doc['url']
            label = url_doc['label']
            
            # Shorten URL for display if too long
            display_url = url if len(url) < 60 else url[:57] + "..."
            
            print(f"\n[{i}/{len(urls_to_process)}] {display_url}")
            print(f"           Label: {label}")
            
            # Process
            success = self.process_single_url(url_doc)
            
            if success:
                successful += 1
                print(f"            Success")
            else:
                failed += 1
                print(f"            Failed")
            
            # Delay between requests (be nice to servers)
            if i < len(urls_to_process):
                time.sleep(delay)
        
        return {
            "processed": len(urls_to_process),
            "successful": successful,
            "failed": failed
        }
    
    def process_all(self, batch_size: int = 50, delay: float = 2.0):
        
       
        print(" STARTING TEXT EXTRACTION PIPELINE")
        
        # Show initial statistics
        self.db.print_statistics()
        
        total_successful = 0
        total_failed = 0
        batch_number = 1
        start_time = time.time()
        
        while True:
            # Get count of remaining URLs
            remaining = len(self.db.get_urls_needing_text_extraction())
            
            if remaining == 0:
                print("\n🎉 All URLs processed!")
                break
            
            print(f"\n" + "="*60)
            print(f" BATCH {batch_number} - {remaining} URLs remaining")
            
            
            batch_start = time.time()
            
            # Process batch
            result = self.process_batch(batch_size=batch_size, delay=delay)
            
            batch_time = time.time() - batch_start
            
            total_successful += result['successful']
            total_failed += result['failed']
            
            print(f"\n Batch {batch_number} Results:")
            print(f"   Successful: {result['successful']}")
            print(f"   Failed: {result['failed']}")
            print(f"   Time: {batch_time:.1f}s")
            
            batch_number += 1
            
            # Small delay between batches
            if remaining > batch_size:
                print(f"\n  Pausing 5 seconds before next batch...")
                time.sleep(5)
        
        # Final statistics
        total_time = time.time() - start_time
        
        print("\n" + "="*60)
        print(" PROCESSING COMPLETE")
        print("="*60)
        print(f"\n Total Results:")
        print(f"   Successful: {total_successful}")
        print(f"   Failed: {total_failed}")
        print(f"   Total Time: {total_time/60:.1f} minutes")
        
        if total_successful + total_failed > 0:
            success_rate = (total_successful/(total_successful+total_failed)*100)
            print(f"   Success Rate: {success_rate:.1f}%")
        
        # Show final database statistics
        self.db.print_statistics()
    
    def close(self):
        
        self.db.close()
        print(" Pipeline closed")


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Training Data Pipeline')
    parser.add_argument('command', choices=['import', 'process', 'stats', 'full'],
                       help='Command to run')
    parser.add_argument('--csv', default='training_urls.csv',
                       help='Path to CSV file (for import command)')
    parser.add_argument('--batch-size', type=int, default=50,
                       help='Batch size for processing')
    parser.add_argument('--delay', type=float, default=2.0,
                       help='Delay between requests in seconds')
    
    args = parser.parse_args()
    
    pipeline = TrainingPipeline()
    
    try:
        if args.command == 'import':
            # Import CSV to MongoDB
            pipeline.import_csv(args.csv)
        
        elif args.command == 'process':
            # Process URLs (extract text)
            pipeline.process_all(batch_size=args.batch_size, delay=args.delay)
        
        elif args.command == 'stats':
            # Show statistics
            pipeline.db.print_statistics()
        
        elif args.command == 'full':
            # Full pipeline: import + process
            pipeline.import_csv(args.csv)
            print("\n⏸  Waiting 3 seconds before starting processing...")
            time.sleep(3)
            pipeline.process_all(batch_size=args.batch_size, delay=args.delay)
    
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user. Progress saved in database.")
        print("💡 Run 'process' command again to resume from where you left off.")
    
    except Exception as e:
        print(f"\n Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        pipeline.close()