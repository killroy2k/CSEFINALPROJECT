import requests, openai, csv, tweepy, sqlite3, os, smtplib, json
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json

from protected_info import *

threat_count = 0


class CVE:
    def __init__(self, id, description, severity, attackVector, attackComplexity, privilegesRequired, userInteraction, confidentialityImpact, integrityImpact, availabilityImpact):
        self.id = id
        self.description = description
        self.severity = severity
        self.attackVector = attackVector
        self.attackComplexity = attackComplexity
        self.privilegesRequired = privilegesRequired
        self.userInteraction = userInteraction
        self.confidentialityImpact = confidentialityImpact
        self.integrityImpact = integrityImpact
        self.availabilityImpact = availabilityImpact

    def __str__(self):
        return "CVE(ID: {self.id}, Severity: {self.severity}, Description: {self.description})"

    
def setup_db():
    print("setting up")
    db_exists = os.path.exists('project.db')
    db = sqlite3.connect('project.db')
    cursor = db.cursor()
    
    if not db_exists:
        cursor.execute('''
            CREATE TABLE cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                attackVector TEXT,
                attackComplexity TEXT,
                privilegesRequired TEXT,
                userInteraction TEXT,
                confidentialityImpact TEXT,
                integrityImpact TEXT,
                availabilityImpact TEXT,
                ai_isthreat_reply TEXT,
                last_modified DATETIME
            )
        ''')
        cursor.execute('''
            CREATE TABLE accuracy (
                source TEXT PRIMARY KEY,
                pass INTEGER,
                fail INTEGER
            )
        ''')
        cursor.execute("INSERT INTO accuracy (source, pass, fail) VALUES ('cisa', 0, 0)")
        db.commit()
    
    return db

#hour diff is used to request entries between current time and (current time - hour_diff)
def check_nvd(hour_diff):
    print("checking")
    # Ensure that hourdiff is a positive integer
    if not isinstance(hour_diff, int) or hour_diff < 0:
        raise ValueError("hourdiff must be a non-negative integer")
    
    # Format the current time and one hour ago in ISO8601 format
    time_now = datetime.utcnow()
    time_diff = time_now - timedelta(hours=hour_diff)
    start = time_diff.strftime('%Y-%m-%dT%H:%M:%S.000')
    end = time_now.strftime('%Y-%m-%dT%H:%M:%S.000')

    #incorrect time format for NVD api 2.0
    # start = time_diff.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    # end = time_now.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    

    # URL for the NVD API, resultsPerPage modified by the source documentation(max= 1000)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start}&lastModEndDate={end}"
    
    #old url
    #url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000"

    # Make the API call
    headers = {'apiKey': API_KEYS._NVD_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch data from NVD: {response.status_code} - {response.text}")
    # print(response.text)

    # Parse the response and create CVE objects
    cve_list = []
    data = response.json()
    with open('test.json', 'w') as f:
        json.dump(data, f, indent =4, sort_keys =True)
    json_list = [data.get("vulnerabilities",{})]
    
    for cve in json_list[0]:
        # print(cve)
        cve_id = cve['cve']['id']
        print(cve_id)
        description = cve['cve']['descriptions'][0]['value']


        #if statement is used to determine which version the cve is graded on (cvssMetricV31 is preferred)
        checkMetric = cve['cve'].get('metrics')
        if checkMetric == {}:
            print("continuing")
            severity = 'UNKNOWN'
            base_score = 'UNKNOWN'
            vector_string = 'UNKNOWN'
            complexity = 'UNKNOWN'
            privileges_required = 'UNKNOWN'
            user_interaction = 'UNKNOWN'
            confidentiality_impact = 'UNKNOWN'
            integrity_impact = 'UNKNOWN'
            availability_impact = 'UNKNOWN'
        else:
            for metricVersion in checkMetric:
                if metricVersion == "cvssMetricV31":
                    metric = 'cvssMetricV31'
                elif metricVersion == "cvssMetricV30":
                    metric = 'cvssMetricV30'
                elif metricVersion == "cvssMetricV2":
                    metric = 'cvssMetricV2'

                severity = cve['cve']['metrics'][metric][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
                base_score = cve['cve']['metrics'][metric][0]['cvssData'].get('baseScore', 'UNKNOWN')
                vector_string = cve['cve']['metrics'][metric][0]['cvssData'].get('vectorString', 'UNKNOWN')
                complexity = cve['cve']['metrics'][metric][0]['cvssData'].get('attackComplexity', 'UNKNOWN')
                privileges_required = cve['cve']['metrics'][metric][0]['cvssData'].get('privilegesRequired', 'UNKNOWN')
                user_interaction = cve['cve']['metrics'][metric][0]['cvssData'].get('userInteraction', 'UNKNOWN')
                confidentiality_impact = cve['cve']['metrics'][metric][0]['cvssData'].get('confidentialityImpact', 'UNKNOWN')
                integrity_impact = cve['cve']['metrics'][metric][0]['cvssData'].get('integrityImpact', 'UNKNOWN')
                availability_impact = cve['cve']['metrics'][metric][0]['cvssData'].get('availabilityImpact', 'UNKNOWN')

        # Initialize the CVE object with the new attributes
        cve_obj = CVE(cve_id, description, severity, vector_string, complexity, privileges_required, 
                      user_interaction, confidentiality_impact, integrity_impact, availability_impact)
        cve_list.append(cve_obj)

    return cve_list

def update_cves_table(new_cves, db):
    print("updoot")
    cursor = db.cursor()
    
    for cve in new_cves:
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        ai_isthreat_reply = check_if_threat(cve)
        cursor.execute('''
            INSERT INTO cves (
                id, description, severity, attackVector, attackComplexity, privilegesRequired,
                userInteraction, confidentialityImpact, integrityImpact, availabilityImpact, ai_isthreat_reply, last_modified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                description=excluded.description,
                severity=excluded.severity,
                attackVector=excluded.attackVector,
                attackComplexity=excluded.attackComplexity,
                privilegesRequired=excluded.privilegesRequired,
                userInteraction=excluded.userInteraction,
                confidentialityImpact=excluded.confidentialityImpact,
                integrityImpact=excluded.integrityImpact,
                availabilityImpact=excluded.availabilityImpact,
                ai_isthreat_reply=excluded.ai_isthreat_reply,
                last_modified=excluded.last_modified
        ''', (
            cve.id, cve.description, cve.severity, cve.attackVector, cve.attackComplexity, cve.privilegesRequired,
            cve.userInteraction, cve.confidentialityImpact, cve.integrityImpact, cve.availabilityImpact, ai_isthreat_reply, current_time
        ))
    
    db.commit()
    print(f"{threat_count}/{len(new_cves)} CVEs found as threats.")

def check_if_threat(cve):
    print("threat to humanity")
    global threat_count

    # # Analyze with OpenAI
    # openai.api_key = API_KEYS._OPENAI_KEY
    # completion = openai.chat.completions.create(
    #     model="gpt-3.5-turbo",
    #     messages=[
    #         {"role": "system", "content": "You are a helpful AI assistant. Given the text input, determine the following about the text: \
    #             Does this represents a cyber security threat? Reply only with 'yes', 'no', or 'unknown'. \
    #         "},
    #         {"role": "user", "content": cve.description}
    #     ],
    #     temperature=1
    # )
    # openai_analysis = completion.choices[0].message.content.lower()
 
    openai_analysis = 'yes'

    # Check if the severity is high enough or OpenAI analysis is 'yes'
    if cve.severity in ["MEDIUM", "HIGH", "CRITICAL"] and openai_analysis == "yes":
        threat_count += 1
        print(send_threat_mail(cve))

    # Return the openai response
    return openai_analysis

#cisa = checking tweets from @cisaCatalogBot
def check_cisa(db, day_diff):
    print("totally the cisa acct")
    # Authenticate with the Twitter API
    client = tweepy.Client(bearer_token=API_KEYS._TWITTER_KEY)

    # Calculate the time range for the previous full day
    end_time = datetime.utcnow()
    end_time = end_time - timedelta(minutes = 1)
    start_time = end_time - timedelta(days=day_diff)
    start_time = start_time - timedelta(minutes = -1)
    # Fetch tweets from the previous full day from CISA Bot ==cisaCatalogBot
    cisa_tweets = client.search_recent_tweets(query="from:CVEnew -is:retweet",
                                              start_time=start_time,
                                              end_time=end_time,
                                              tweet_fields=['created_at'],
                                              max_results=100)  # Adjust max_results as necessary

    cursor = db.cursor()
    pass_count = 0
    fail_count = 0

    # Check if cisa_tweets.data is not None
    if cisa_tweets.data:
        # Check if each CVE mentioned in CISA tweets exists in the database
        for tweet in cisa_tweets.data:
            # print(str(tweet) + "\n")
            cve_id = tweet.text.split()[0]  # Assuming the CVE ID is the first word in the tweet
            cursor.execute("SELECT count(1) FROM cves WHERE id = ?", (cve_id,))
            exists = cursor.fetchone()[0]

            # Update pass/fail counts
            if exists:
                pass_count += 1
            else:
                fail_count += 1
    else:
        print("No data returned from Twitter API")

    # Update accuracy metrics in the database and get response
    db_response = update_cisa_accuracy(pass_count, fail_count, db)
    print(f"Pass count: {pass_count}, Fail count: {fail_count}")
    return db_response

def update_cisa_accuracy(pass_count, fail_count, db):
    print("acc updoot")
    try:
        # Update pass and fail counts in your 'cisa_accuracy' table
        cursor = db.cursor()
        cursor.execute("UPDATE accuracy SET pass = pass + ?, fail = fail + ?", (pass_count, fail_count))
        db.commit()
        return f"Database updated successfully with {pass_count} passes and {fail_count} fails."
    except Exception as e:
        return f"An error occurred: {e}"
    
def get_cisa_accuracy(db):
    print("fetch acc")
    cursor = db.cursor()
    cursor.execute("SELECT pass, fail FROM accuracy WHERE source = 'cisa'")
    row = cursor.fetchone()
    
    if row:
        pass_count, fail_count = row
        if pass_count + fail_count > 0:
            accuracy_percent = (pass_count / (pass_count + fail_count)) * 100
        else:
            raise ValueError("CISA accuracy calculation error: No passes or fails recorded.")
        return accuracy_percent
    else:
        raise ValueError("CISA accuracy record not found.")

def send_threat_mail(cve):
    print("sending threat email")
    try:
        # Setup email server connection
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        secret = EMAIL_INFO()  # Access protected variables in diff file
        server.login(secret._HOST_EMAIL, secret._HOST_PASSWORD)

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Threat Alert: {cve.id} - Severity: {cve.severity}"
        msg['From'] = secret._HOST_EMAIL
        msg['To'] = ", ".join(secret._RECEIVER_EMAILS)

        # HTML Email body
        html_body = f"""\
        <html>
            <body>
                <p style="font-size: 16px;">
                    <strong>Threat Report:</strong><br><br>
                    <strong>CVE ID:</strong> {cve.id}<br>
                    <strong>Description:</strong> {cve.description}<br>
                    <strong>Severity:</strong> {cve.severity}<br>
                    <strong>Attack Vector:</strong> {cve.attackVector}<br>
                    <strong>Attack Complexity:</strong> {cve.attackComplexity}<br>
                    <strong>Privileges Required:</strong> {cve.privilegesRequired}<br>
                    <strong>User Interaction:</strong> {cve.userInteraction}<br>
                    <strong>Confidentiality Impact:</strong> {cve.confidentialityImpact}<br>
                    <strong>Integrity Impact:</strong> {cve.integrityImpact}<br>
                    <strong>Availability Impact:</strong> {cve.availabilityImpact}<br>
                </p>
            </body>
        </html>
        """

        part = MIMEText(html_body, 'html')
        msg.attach(part)

        # Send email
        server.sendmail(from_addr=secret._HOST_EMAIL, to_addrs=secret._RECEIVER_EMAILS, msg=msg.as_string())
        server.quit()
        
        return "Email sent successfully."
    except Exception as e:
        return f"Failed to send email: {e}"

def send_report_mail(db):
    print("sending report email")
    try:
        # Get the CISA accuracy percentage
        cisa_accuracy_percent = get_cisa_accuracy(db)

        # Calculate the time range for the previous full day
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)

        # Query the database for CVEs added or modified in the last day
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, description, severity, attackVector, attackComplexity, privilegesRequired,
                   userInteraction, confidentialityImpact, integrityImpact, availabilityImpact, ai_isthreat_reply
            FROM cves
            WHERE last_modified >= ? AND last_modified < ?""",
            (start_time.strftime("%Y-%m-%d %H:%M:%S"), end_time.strftime("%Y-%m-%d %H:%M:%S")))
        
        cve_list = cursor.fetchall()

        # Create a CSV file and write the data
        csv_file = "cve_report.csv"
        with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Description", "Severity", "Attack Vector", "Attack Complexity", "Privileges Required",
                             "User Interaction", "Confidentiality Impact", "Integrity Impact", "Availability Impact", "Threat Status"])
            for cve in cve_list:
                threat_status = 'Threat' if cve[10] else 'Not a Threat'
                writer.writerow(list(cve)[:-1] + [threat_status])  # Append 'threat_status' instead of 'ai_isthreat_reply'

        # Setup email server connection
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        secret = EMAIL_INFO()
        server.login(secret._HOST_EMAIL, secret._HOST_PASSWORD)

        msg = MIMEMultipart()
        msg['Subject'] = 'Daily CVE Report'
        msg['From'] = secret._HOST_EMAIL
        msg['To'] = ", ".join(secret._RECEIVER_EMAILS)

        # HTML Email body
        html_body = f"""\
        <html>
            <body>
                <p style="font-size: 16px;">
                    <strong>Daily CVE Threat Report for the Last Full Day:</strong><br><br>
                    <strong>CISA Catalog Accuracy:</strong> {cisa_accuracy_percent:.2f}%<br>
                    Attached is the CVE report in CSV format.<br>
                </p>
            </body>
        </html>
        """

        part = MIMEText(html_body, 'html')
        msg.attach(part)

        # Attach the CSV file
        with open(csv_file, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {csv_file}")
        msg.attach(part)

        # Send email
        server.sendmail(from_addr=secret._HOST_EMAIL, to_addrs=", ".join(secret._RECEIVER_EMAILS), msg=msg.as_string())
        server.quit()
        
        return "Email sent successfully."
    except ValueError as e:
        return f"Error while calculating CISA accuracy: {e}"
    except Exception as e:
        return f"Failed to send email: {e}"

def fetch_all_rows(db, table_name):
    cursor = db.cursor()
    query = f"SELECT * FROM {table_name}"
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return rows
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def print_table(db, table_name):
    rows = fetch_all_rows(db, table_name)
    if rows:
        for row in rows:
            print(row)
    else:
        print("No data found in the table.")