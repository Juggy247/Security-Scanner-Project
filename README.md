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
        > suspicious_tlds
        > brands
        > blacklisted_domains
        > suspicious_keywords
        > config_history
    - The Python code automatically creates these collections, you do not have to create them.
    - Checking them in Terminal

            mongo
            use security_scanner
            show collections
      
  # Run the Project

      python3.11 app.py 
