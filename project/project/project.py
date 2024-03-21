import requests, openai, csv, tweepy, sqlite3, os, smtplib, json
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from cvss import CVSS3,CVSS4

from protected_info import *

threat_count = 0


class CVE:
    def __init__(self, id, description, severity, attackVector, attackComplexity, privilegesRequired, userInteraction, confidentialityImpact, integrityImpact, availabilityImpact, openai_description, gpt_response, calc_score_based_on_ai=0):
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
        self.openai_description = openai_description
        self.gpt_response = gpt_response
        self.calc_score_based_on_ai = calc_score_based_on_ai

    def __str__(self):
        return "CVE(ID: {self.id}, Severity: {self.severity}, Description: {self.description})"

    
def setup_db():
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
                gpt_response TEXT,
                openai_description TEXT,
                calc_score_based_on_ai TEXT,
                last_modified DATETIME
            )
        ''')

        db.commit()
    
    return db

#hour diff is used to request entries between current time and (current time - hour_diff)
def check_nvd(hour_diff):
    # Ensure that hourdiff is a positive integer
    if not isinstance(hour_diff, int) or hour_diff < 0:
        raise ValueError("hourdiff must be a non-negative integer")
    
    # Format the current time and one hour ago in ISO8601 format
    time_now = datetime.utcnow()
    time_diff = time_now - timedelta(hours=hour_diff)
    start = time_diff.strftime('%Y-%m-%dT%H:%M:%S.000')
    end = time_now.strftime('%Y-%m-%dT%H:%M:%S.000')

    # URL for the NVD API, resultsPerPage modified by the source documentation(max= 1000)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start}&pubEndDate={end}"
    
    # Make the API call
    headers = {'apiKey': API_KEYS._NVD_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch data from NVD: {response.status_code} - {response.text}")
    # print(response.text)

    # Parse the response and create CVE objects
    cve_list = []
    data = response.json()
    # with open('test.json', 'w') as f:
    #     json.dump(data, f, indent =4, sort_keys =True)
    json_list = [data.get("vulnerabilities",{})]
    
    for cve in json_list[0]:
        # print(cve)
        cve_id = cve['cve']['id']
        # print(cve_id)
        description = cve['cve']['descriptions'][0]['value']

        #if statement is used to determine which version the cve is graded on (cvssMetricV31 is preferred)
        checkMetric = cve['cve'].get('metrics')
        if checkMetric == {}:
            # print("continuing")
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
                      user_interaction, confidentiality_impact, integrity_impact, availability_impact,openai_description="", gpt_response="", calc_score_based_on_ai=0)
        cve_list.append(cve_obj)

    return cve_list

def update_cves_table(new_cves, db):
    print("updating cves table")
    cursor = db.cursor()
    
    for cve in new_cves:
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        gpt_response = check_if_threat(cve)
        calc_score_based_on_ai = calculate_cvss_score(gpt_response)
        cve.calc_score_based_on_ai = calc_score_based_on_ai

        if cve.calc_score_based_on_ai is None:
            print(f"Skipping {cve.id} due to an error in the CVSS calculation.")
            continue

        #Update the severity based on the calculated score
        if cve.calc_score_based_on_ai < 3.9:
            cve.severity = "LOW"
        elif cve.calc_score_based_on_ai < 7.0:
            cve.severity = "MEDIUM"
        elif cve.calc_score_based_on_ai < 9.0:
            cve.severity = "HIGH"
        elif cve.calc_score_based_on_ai <= 10.0:
            cve.severity = "CRITICAL"

        cursor.execute('''
            INSERT INTO cves (
                id, description, severity, attackVector, attackComplexity, privilegesRequired,
                userInteraction, confidentialityImpact, integrityImpact, availabilityImpact, gpt_response, openai_description, calc_score_based_on_ai, last_modified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                gpt_response=excluded.gpt_response,
                openai_description=excluded.openai_description,
                calc_score_based_on_ai=excluded.calc_score_based_on_ai,
                last_modified=excluded.last_modified
        ''', (
            cve.id, cve.description, cve.severity, cve.attackVector, cve.attackComplexity, cve.privilegesRequired,
            cve.userInteraction, cve.confidentialityImpact, cve.integrityImpact, cve.availabilityImpact, gpt_response, cve.openai_description, calc_score_based_on_ai,current_time
        ))

        send_threat_mail(cve)
    
    db.commit()
    print(f"{threat_count}/{len(new_cves)} CVEs found as threats.")

def check_if_threat(cve):
    print("check if threat 183")
    global threat_count

    # Analyze with OpenAI
    openai.api_key = API_KEYS._OPENAI_KEY
    completion = openai.chat.completions.create(
        model="ft:gpt-3.5-turbo-0125:personal::94gKPRse",
        messages=[
            {"role": "system", "content": "You are a helpful CVSS assistant. Given the text input, determine the following about the text: \
                Generate the complete eight field 3.1 CVSS vector string based off this description.\
                Only provide AV, AC, PR, UI, S, C, I, A values, an example: AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X\
            "},
            {"role": "user", "content": cve.description}
        ],
        temperature=1
    )

    print("rated severity: " + cve.severity)
    openai_analysis = completion.choices[0].message.content.lower()
    cve.gpt_response = openai_analysis.upper()  # Store the generated attack vector in the CVE object
    print("chatgpt returns: " + openai_analysis)
    
    threat_count += 1
    # print(send_threat_mail(cve))
    # print(cve.id + " , " +cve.description + " , " + cve.severity + " , " + cve.attackVector + " , " + cve.attackComplexity + " , " + cve.privilegesRequired + " , " + cve.userInteraction + " , " + cve.confidentialityImpact + " , " + cve.integrityImpact + " , " + cve.availabilityImpact)
    print("cve id: " + cve.id + " gpt response: " + openai_analysis.upper())

    cve.openai_description = openai_generate_cve_description(cve)
    
    # Return the openai response
    return openai_analysis

def openai_generate_cve_description(cve):
    print("line 217 openai generate cve desc")

    openai.api_key = API_KEYS._OPENAI_KEY
    completion = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful CVSS assistant. Given the text input, determine the following about the text: \
                Generate a complete description of this CVE, and possible solutions(separated by line breaks), as if I am a client for a cybersecurity firm\
                refrain from using jargon and go into length to be descriptive\
            "},
            {"role": "user", "content": "Threat level:" + cve.severity + "CVE ID:" + cve.id + "Description:" + cve.description}
        ],
        temperature=1
    )

    print(completion.choices[0].message.content)
    return completion.choices[0].message.content

def calculate_cvss_score(openai_analysis):
    print("\n")
    scope = "S:"
    if len(openai_analysis) > 35:
        # vector = openai_analysis.split("/") #may just be an error string instead of the optimized attack vector
        print("error finding score: attack vector not optimized for base score calculation")
        return None
    elif scope.lower() in openai_analysis.lower():
        print("3.0: ", openai_analysis)
        vector = 'CVSS:3.0/' + openai_analysis.upper()
        c= CVSS3(vector)
        print(c.scores()[0])
        return c.scores()[0]
    elif "4.0" in openai_analysis: #if the vector given by openai is cvss 4.0 then the following code will be used
        print("4.0: ", openai_analysis)
        # vector = 'CVSS:4.0/' + openai_analysis
        c = CVSS4(openai_analysis)
        return c.base_score

# WRITE DISCLAIMER (INACCURATE RESULTS)
def send_threat_mail(cve):
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

        # Convert OpenAI description to HTML output including linebreaks
        openai_description_html = cve.openai_description.replace('\n', '<br>')

        # HTML Email body
        html_body = f"""\
        <html>
            <body>
                <p style="font-size: 16px;">
                    <strong><u>DISCLAIMER: The following report is AI Generated and may have\
                        incorrect or misleading information</u></strong><br><br>
                    <strong>Threat Report:</strong><br>
                    <strong>CVE ID:</strong> {cve.id}<br>
                    <strong>Generated Score:</strong> {cve.calc_score_based_on_ai}<br>
                    <strong>Severity:</strong> {cve.severity}<br>
                    <strong>Generated Description and Solutions:</strong> <br>{openai_description_html}<br>
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