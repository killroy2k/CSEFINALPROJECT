CVE Monitoring Project
======================

Description
-----------

This project includes scripts for monitoring and reporting Common Vulnerabilities and Exposures (CVEs). It consists of one main Python scripts:

*   `threat_check.py`: Checks for new CVEs every hour and updates the database accordingly.

Prerequisites
-------------

To run this project, you need to have the following installed:

*   Python 3.x
*   SQLite3
*   Required Python packages: `requests`, `openai`, `smtplib`

Setup
-----

1.  **Unzip code files:** Choose the location you want to unzip the code files and unzip the folder.
    
    bashCopy code
    
    `unzip project.zip`
    
2.  **Install Python 3:** Ensure Python 3.x is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).
    
3.  **Set Up a Virtual Environment (Optional):** It's a good practice to use a virtual environment. Run the following commands to create and activate one:
    
    bashCopy code
    
    `` python3 -m venv venv source venv/bin/activate  # On Windows, use `venv\Scripts\activate` ``
    
4.  **Install Required Python Packages:** Install all required packages using pip:
    
    bashCopy code
    
    `pip install requests openai`
    
5.  **Database Setup:** The project uses SQLite. Ensure SQLite3 is installed on your system.
    
6.  **Configuration:**
    
    *   Set up `protected_info.py` with your API keys and email information.
    *   Ensure `project.py` has the correct paths and configurations.
    
7.  **Crontab Setup (Unix-based systems):** To schedule the scripts, set up cron jobs:
    
    *   Edit your crontab: `crontab -e`
    *   Add the following lines, replacing `/path/to/script` with the actual paths:
        
        rubyCopy code
        
        `# Run threat_check.py every hour 0 * * * * /usr/bin/python3 /path/to/threat_check.py`
        

Usage
-----

*   **Running Scripts Manually:** To run the scripts manually, execute the following commands:
    
    bashCopy code
    
    `python3 threat_check.py`
    
*   **Automated Execution:** If you have set up crontab as per the setup instructions, the scripts will run automatically at the specified times.
    

Notes
-----

*   Make sure the system where the scripts are running has internet access, as the scripts need to make API calls.
*   If you face any permission issues while running the scripts, you may need to adjust file permissions or run the scripts with appropriate user permissions.

