import requests
import pandas as pd
from datetime import datetime
import time

class URLCollector:
    def __init__(self):
        self.safe_urls = []
        self.dangerous_urls = []
    
    def collect_safe_sites(self, limit=200):
        
        #print("Download Start")
        try: 
            url = "https://tranco-list.eu/top-1m.csv.zip"
            #print("can download\n")

            df = pd.read_csv(
                url,
                compression="zip",
                header=None, 
                names=['rank','domain']
                )
            
            top_domains = df.head(limit)['domain'].tolist()
            self.safe_urls = [f"https://{domain}" for domain in top_domains]

            print("Success! ")
            return self.safe_urls
        
        except Exception:
            print("Error Occur! ")
            return []
        
    def collect_dangerous_sites(self, source_name, url, parser, limit=200):
        #print("Download Start")

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            urls = parser(response) 
            urls = urls[:limit]
            
            self.dangerous_urls.extend(urls)

            print("Succeed!")
            return urls
            
        except Exception as e:
            print("Failed!")
            return []
        
    def parse_phishtank(self, response):
        data = response.json()
        urls = []
        for entry in data:
            urls.append(entry['url'])
        return urls

    def parse_openphish(self, response):
        urls = []
        lines = response.text.split("\n")
        for line in lines:
            clean_line = line.strip()
            if clean_line:
                urls.append(clean_line)
        return urls
        
    def parse_urlhaus(self, response):
        lines = response.text.split("\n")
        urls = []
        for line in lines:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                urls.append(clean)
        return urls


    def save_to_csv(self, filename="training_urls.csv"): 

        print(f"\n💾 Saving URLs to {filename}...") 
        data = [] 
        for url in self.safe_urls: 
            data.append({ 
                'url': url,
                'label': 'safe',
                'source': 'tranco',
                'date_collected': datetime.now().isoformat() }) 
        
        for url in self.dangerous_urls: 
            data.append({ 
                'url': url,
                'label': 'dangerous',
                'source': 'phishing_database',
                'date_collected': datetime.now().isoformat() 
            }) 
            
        df = pd.DataFrame(data).drop_duplicates(subset=['url']) 
        df.to_csv(filename, index=False) 
        print(f" Saved {len(df)} URLs to {filename}") 
        print(f" Safe: {len(df[df['label'] == 'safe'])}") 
        print(f" Dangerous: {len(df[df['label'] == 'dangerous'])}") 
        return filename 
    
    def collect_all(self, safe_count=200, dangerous_count=200):
        
        self.collect_safe_sites(limit=safe_count)

        #Note: 70% from phishtank and 30% from openphish
        #phishtank_count = int(dangerous_count * 0.7)
        urlhaus_count = int(dangerous_count * 0.5)
        openphish_count = dangerous_count - urlhaus_count

        #PhishTank
        '''
        self.collect_dangerous_sites(
            source_name="PhishTank",
            url="http://data.phishtank.com/data/online-valid.json",
            parser=self.parse_phishtank,
            limit=phishtank_count
        )
        '''
        #urlhaus
        self.collect_dangerous_sites( 
            source_name="URLHaus", 
            url="https://urlhaus.abuse.ch/downloads/text/", 
            parser=self.parse_urlhaus, 
            limit=urlhaus_count 
        )

        time.sleep(2)

        #OpenPhish
        self.collect_dangerous_sites(
            source_name="OpenPhish",
            url="https://openphish.com/feed.txt",
            parser=self.parse_openphish,
            limit=openphish_count
        )

        
        filename = self.save_to_csv()

        return filename

def main():
    collector = URLCollector()
    collector.collect_all(safe_count=200, dangerous_count=200)
    
if __name__ == "__main__":
    main()
    
    
    

