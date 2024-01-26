from requests.auth import HTTPBasicAuth
import requests, openai, csv, tweepy, sqlite3, os, smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json

from protected_info import *
from project import *

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

    #incorrect time format for NVD api 2.0
    # start = time_diff.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    # end = time_now.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    

    # URL for the NVD API, resultsPerPage modified by the source documentation(max= 1000)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start}&lastModEndDate={end}"
    print(url)
    
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
        #have to create a separate section for cvssMetricV2
        severity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
        base_score = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('baseScore', 'UNKNOWN')
        vector_string = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('vectorString', 'UNKNOWN')
        complexity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('attackComplexity', 'UNKNOWN')
        privileges_required = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('privilegesRequired', 'UNKNOWN')
        user_interaction = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('userInteraction', 'UNKNOWN')
        confidentiality_impact = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('confidentialityImpact', 'UNKNOWN')
        integrity_impact = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('integrityImpact', 'UNKNOWN')
        availability_impact = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData'].get('availabilityImpact', 'UNKNOWN')

        # Initialize the CVE object with the new attributes
        cve_obj = CVE(cve_id, description, severity, vector_string, complexity, privileges_required, 
                      user_interaction, confidentiality_impact, integrity_impact, availability_impact)
        print(cve_obj)
        cve_list.append(cve_obj)

    return cve_list


cveList = check_nvd(2)
# print(len(cveList))