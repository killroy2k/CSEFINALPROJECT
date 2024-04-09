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
        
        `# Run threat_check.py every hour 0 * * * * /usr/bin/python3 /path/to/threat_check.py  # Run daily_report.py once a day at 8 AM 0 8 * * * /usr/bin/python3 /path/to/daily_report.py`
        
8.  **Task Scheduler Setup (Windows-based systems):** To schedule the scripts, set up the task:

        ***Not tested but seen in video...Let the task run for at least a day before it becomes operational***

    * Click "Create Task" to create a new task
    * Add name to task such as "30 min threat check" and (optional) add a description
    
    # * Under more testing, Give it high priviledges * #

    * Add trigger and set it to daily and set a time
            ** Make sure that the option "Repeat task every:" is selected and set time to 30 minutes for a duration of indefinitely
            ** Make sure that it is ENABLED
    * Add an action
            **IF PATH CONTAINS SPACES ENCLOSE PATH IN QUOTES ("")**
            Under "Program/Script":
                insert location of python.exe file
                **IF UNSURE OF LOCATION**
                    Open "Command Prompt" and type "where python"

                    copy path of the most recent python version given and insert it to under Program/Scipt

            Under "Add arguments"
                insert the path to "threat_check.py"

        
    * Modify any conditions in the CONDITIONS tab if needed

    * select ok and wait for the next day for full functionality (unconfirmed, testing rn)


    # To manually run the task:
        after creating the task following the steps above









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
