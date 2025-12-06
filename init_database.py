import logging
from scanner.config import MongoDbConfig

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def main():
    print(" Initializing Security Scanner Database")
    print()
    
    try:
        # Connect to MongoDB
        config = MongoDbConfig()
    
        
        #TLDs

        print("Adding TLDs...")
        tlds = [
            {'tld': 'tk', 'risk_level': 'critical', 'reason': 'Free domain, 72% abuse rate'},
            {'tld': 'ml', 'risk_level': 'critical', 'reason': 'Free domain, 68% abuse rate'},
            {'tld': 'ga', 'risk_level': 'critical', 'reason': 'Free domain, 65% abuse rate'},
            {'tld': 'cf', 'risk_level': 'critical', 'reason': 'Free domain, 60% abuse rate'},
            {'tld': 'gq', 'risk_level': 'critical', 'reason': 'Free domain, 58% abuse rate'},
            {'tld': 'zip', 'risk_level': 'high', 'reason': 'Confused with file format'},
            {'tld': 'mov', 'risk_level': 'high', 'reason': 'Confused with video format'},
            {'tld': 'xyz', 'risk_level': 'medium', 'reason': 'Cheap domain'},
            {'tld': 'top', 'risk_level': 'medium', 'reason': 'Cheap domain'},
            {'tld': 'click', 'risk_level': 'medium', 'reason': 'Clickbait abuse'},
        ]
        tld_count = config.add_multiple_tlds(tlds)
        print(f" Added {tld_count} TLDs")
        
        # brands
        print("\nAdding Brands")
        brands = [
            {'brand_name': 'paypal', 'category': 'payment'},
            {'brand_name': 'stripe', 'category': 'payment'},
            {'brand_name': 'google', 'category': 'technology'},
            {'brand_name': 'microsoft', 'category': 'technology'},
            {'brand_name': 'apple', 'category': 'technology'},
            {'brand_name': 'amazon', 'category': 'ecommerce'},
            {'brand_name': 'facebook', 'category': 'social_media'},
            {'brand_name': 'instagram', 'category': 'social_media'},
            {'brand_name': 'secure', 'category': 'keyword'},
            {'brand_name': 'login', 'category': 'keyword'},
            {'brand_name': 'verify', 'category': 'keyword'},
            {'brand_name': 'account', 'category': 'keyword'},
        ]
        brand_count = config.add_multiple_brands(brands)
        print(f"Added {brand_count} brands")
        
        #KEYWORDS 
        print("\nAdding Suspicious Keywords...")
        keywords = [
            {'keyword': 'verify', 'category': 'action_words'},
            {'keyword': 'confirm', 'category': 'action_words'},
            {'keyword': 'update', 'category': 'action_words'},
            {'keyword': 'secure', 'category': 'trust_words'},
            {'keyword': 'official', 'category': 'trust_words'},
            {'keyword': 'account', 'category': 'service_words'},
            {'keyword': 'banking', 'category': 'service_words'},
            {'keyword': 'payment', 'category': 'service_words'},
        ]
        kw_count = config.add_multiple_keywords(keywords)
        print(f" Added {kw_count} keywords")
        
       
       
        print(" Database Initialized Successfully!")
        print(f"   TLDs: {tld_count}")
        print(f"   Brands: {brand_count}")
        print(f"   Keywords: {kw_count}")
        print()
        
        
        config.close()
        return 0
  
    except Exception as e:
        print()
        print(" Error:", e)
        print()
        print("Make sure MongoDB is running:")
        return 1


if __name__ == "__main__":
    exit(main())