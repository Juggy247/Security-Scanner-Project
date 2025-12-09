# Project Name - Security Scanner

Group - 10 

***Team members - Thu Htoo Zaw, Thiri Toe Toe Zin, Bhone La Pyae, Thet Su Win***

# Project Idea
  Our project idea is to create a web-based security scanner application that checks whether a website is secure or not. The main goal of this application is to help users easily identify potential security risks in any website by simply entering its URL.

# Technology Stacks

 - Programming Language: Python
 - Web Framework: Flask
 - Web Scraping & HTTP: Requests, BeautifulSoup
 - Database: MongoDB with PyMongo
 - Domain & DNS Analysis: dnsPython, python-whois
 - Security & API Tools: Flask-Limiter, Flask-CORS, Flasgger
 
We use Python as the main programming language and Flask as the web framework for building the web-based security scanner.

# Main Challenges

Our initial challenge was understanding various website security measures, implementing checks for HTTPS, SSL, and headers, and learning to handle forms, titles, and different website structures.

- Timeouts and connectivity problems
- robots.txt restrictions
- Data inconsistencies
- Database reliability
- Lack of reliable test websites or sample data

# Foreseen Challenges

Lack of test data is still one of our main challenges. When scanning for phishing websites using TLDs, keywords, or brand names, our database contains limited records. 

***Potential Challenges***

- Machine Learning Integration
- Advanced Security Detection
- Improving Accuracy
- improvement on reporting system
- More error handling for various websites structures

# Our current Stage


# Some of our Solutions to our Problems

***Bypassing robots.txt Restrictions:***
Some websites block automated scans via robots.txt, which can limit testing.
Our scanner checks robots.txt first. If scanning is restricted, we can bypass it during controlled testing.

***Handling Timeouts and Connectivity Issues:***
We use python request library with custom request timeouts to avoid hanging indefinitely.

***Homograph and Phishing Detection:***
We implemented checks using TLDs, keywords, blacklisted domains, and brand names stored in our database. However, we still face challenges in gathering comprehensive data for our collections, as there are many brands and potentially unknown keywords or TLDs that aren’t yet included.

***Error Handling & Dynamic Websites***
All the network requests are wrapped in try/except block in order to prevent crashes.
Our current implementation works well on static and semi-dynamic websites. Although there are limitations, such as scanning fully dynamic, JavaScript-heavy websites, they may not be fully scanned, and we will need to improve this.
