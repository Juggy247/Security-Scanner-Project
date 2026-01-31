# Setting Up the Project
  - Disclaimer: We use python version 3.11 in this project, your command should be python3.11 code.py
    
  # Create & Activate a Virtual Environment

  - Please the delete the venv folder after you downloaded the project.
  - You will have to create you own virtual enviroment.

        # Create virtual environment
        python -m venv venv
      
        # Activate virtual environment
        venv\Scripts\activate

        #How to deactivate
        deactivate

# Install Dependencies from requirements.txt

    pip install -r requirements.txt

If this does not work we will have to install them by,  

    pip install flask==3.0.0
    pip install beautifulsoup4==4.12.2
    pip install requests==2.31.0
    pip install pymongo==4.6.0
    pip install dnspython==2.4.2
    pip install python-whois==0.8.0
    pip install tensorflow==2.15.0
    pip install scikit-learn==1.3.2
    pip install pandas==2.1.3
    pip install numpy==1.26.2
    pip install flask-limiter==3.5.0
    pip install flask-cors==4.0.0
    pip install flasgger==0.9.7.1

#Important Note

Please ignore files or folder that contain ml/ML or datacollections because they are currently in development.

# Setting up Database

  - Install mongoDb
    - MacOs

          brew tap mongodb/brew
          brew install mongodb-community@7.0
          brew services start mongodb-community@7.0
      
    - Window
    - Download MongoDB from https://www.mongodb.com/try/download/community
    - Run the installer and choose “Complete”
    - Start MongoDB service via Command Prompt:
   
          net start MongoDB
      
  - Creating Collections
    - Your project uses a database called security_scanner with the following collections:
        - suspicious_tlds
        - brands
        - blacklisted_domains
        - suspicious_keywords
        - config_history
    - The Python code automatically creates these collections, you do not have to create them.
    - Checking them in Terminal

            mongo
            use security_scanner
            show collections
      
  # Run the Project

      python3.11 app.py 
