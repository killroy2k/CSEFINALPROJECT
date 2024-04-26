CVE Automated Monitoring Project
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
*   Required Python packages: `requests`, `openai`, `cvss`, `psycopg2`, `psycopg2.binary`


AWS Deployment
-----

1. First you would want to provision an AWS RDS Postgres database and create a table otherwise the app creates one itself, source: https://www.youtube.com/watch?v=I_fTQTsz2nQ

    db = psycopg2.connect( dbname='project_db', user='postgres', password='USFFINALPROJ', host='database-2.crwmu0s8imjf.us-east-2.rds.amazonaws.com', port='5432')

Above is line 37 of project.py which is the line that connects to the DB itself, and this can be moved to protected_info.py or updating the values here

Get the necessary input data from RDS such as the DB name, the db user name and password, the host (or the host link from AWS), and the port (5432 is the default).

2. Create an S3 bucket and push the folder that holds the application code there

3. Provision an EC2 (Elastic Cloud Compute) instance and make sure the security group has access to the S3 bucket

    Make sure your security group has access to your s3 bucket from ec2

4. In EC2 update the instance:

        `sudo yum update`

    Also install the libraries mentioned above onto the EC2 instance

    and then create a directory and navigate to it, once you are in it, get the s3 bucket link where you uploaded your application code to, and then run the following command to push the code to your ec2 instance:

        `aws s3 sync s3://bucket-arn-link . `

    this command gets objects from the s3 bucket and copies it to the current directory


5. Follow the proceding steps `Local Setup` as a guide to running the application on ec2

    Step 6 details making the project automatic



Local Setup
-----

1.  **Unzip code files (if zipped):** Choose the location you want to unzip the code files and unzip the folder.
    
    bashCopy code
    
    `unzip project.zip`
    
2.  **Install Python 3:** Ensure Python 3.x is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

3.  **Install Required Python Packages:** Install all required packages using pip:
    
    bashCopy code
    
    `pip install -r requirements.txt`

    or 

    `pip install [packages]`
    
4.  **Database Setup:** The project uses postgresql version 16. Ensure postgresql version 16 is installed on your system (https://www.postgresql.org/download/). Also make sure that you change the "dbname", "password", and "host" to your corresponding values.
    
5.  **Configuration:**
    
    *   Set up `protected_info.py` with your API keys and email information.
    *   Ensure `project.py` has the correct paths and configurations.
    

6.  **Crontab Setup (Unix-based systems):** To schedule the scripts, set up cron jobs:

    *   Start the crontab service: `sudo service crond start`
    *   Edit your crontab: `crontab -e`
    *   Add the following lines, replacing `/path/to/script` with the actual paths:
        
        `0 * * * * python3 /path/to/threat_check.py`

    *   This current runs the program at the start of every hour



Usage
-----

*   **Running Scripts Manually:** To run the scripts manually, execute the following commands:

    `python3 threat_check.py`
    
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

*also maybe need a NVD/OpenAI APIs are up to date

