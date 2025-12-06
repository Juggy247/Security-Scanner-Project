from scanner.config import MongoDbConfig

config = MongoDbConfig()

config.add_brand('Mango', category='Clothing_brand', priority='low')
config.add_suspicious_keyword('billing', category='service_words')
#config.add_suspicious_keyword('address', category='service_words')

#config.add_blacklisted_domain('evil123-site.tk', source='manual', reason='Phishing site')

#config.add_blacklisted_domain('example.com', source='manual', reason='Testing blacklist')


config.close()