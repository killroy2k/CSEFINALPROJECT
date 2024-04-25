CVE Monitoring Project
======================

Description
-----------

This project includes a script for monitoring and reporting Common Vulnerabilities and Exposures (CVEs). It consists of two main Python scripts:

*   `threat_check.py`: Checks for new CVEs every hour and updates the database accordingly.

Prerequisites
-------------

To run this project, you need to have the following installed:

*   Python 3.x
*   postgresql Version 16
*   Required Python packages: `requests`, `openai`, `tweepy`, `smtplib`

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
    
    `pip install -r requirements.txt`
    
5.  **Database Setup:** The project uses postgresql version 16. Ensure postgresql version 16 is installed on your system (https://www.postgresql.org/download/). Also make sure that you change the "dbname", "password", and "host" to your corresponding values.
    
6.  **Configuration:**
    
    *   Set up `protected_info.py` with your API keys and email information.
    *   Ensure `project.py` has the correct paths and configurations.
    
7.  **Crontab Setup (Unix-based systems):** To schedule the scripts, set up cron jobs:
    
    *   Edit your crontab: `crontab -e`
    *   Add the following lines, replacing `/path/to/script` with the actual paths:
        
        rubyCopy code
        
        `# Run threat_check.py every hour 0 * * * * /usr/bin/python3 /path/to/threat_check.py`
        
8.  **Task Scheduler Setup (Windows-based systems):** To schedule the scripts, set up the task:

    # If device is not functional at all times, set start time ahead of current time. #
       ## for example, if the device is functional during 3:55 pm, set start time to 4:00 pm ##

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
        after creating the task following the steps above, click run on the right hand side of the task scheduler



Usage
-----

*   **Running Scripts Manually:** To run the scripts manually, execute the following commands:
    
    bashCopy code
    
    `python3 daily_report.py python3 threat_check.py`
    
*   **Automated Execution:** If you have set up crontab as per the setup instructions, the scripts will run automatically at the specified times.

*   **Finding the Database** To find the database follow the following steps:

    Go to the location you saved PostgreSQL (typically it is in "Programs Files") and open
    -> Open the 16 file
    -> Open pgAdmin 4
    -> Open runtime
    -> Open PgAdmin4 application
    -> Click Object
    -> Click Register
    -> Click Server
    -> Put the name of your database in the name section (default project_db)
    -> Click Connection
    -> Add your host address
    -> Add the password
    -> Click Save
    -> Now the database should show up under your servers now that you are connected to the database the next steps will show you how to look at it
        -> Double click the name you gave when setting up the connection
        -> Double click Databases
        -> Double click the actual database (default name project_db)
        -> Double click Schemas
        -> Double click Tables
        -> Left click cve and select View
        -> Click view all
    

Notes
-----

*   Make sure the system where the scripts are running has internet access, as the scripts need to make API calls.
*   If you face any permission issues while running the scripts, you may need to adjust file permissions or run the scripts with appropriate user permissions.

*   When downloading postgresql make sure to download all the files from the installer, especially pgAdmin4

*also maybe need a Twitter/API that is up to date