import requests, openai, csv, tweepy, sqlite3, os, smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from protected_info import *

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

def check_nvd(hour_diff):
    # Ensure that hourdiff is a positive integer
    if not isinstance(hour_diff, int) or hour_diff < 0:
        raise ValueError("hourdiff must be a non-negative integer")
    
    # Format the current time and one hour ago in ISO8601 format
    time_now = datetime.utcnow()
    time_diff = time_now - timedelta(hours=hour_diff)
    start = time_diff.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    end = time_now.strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')

    # URL for the NVD API
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000"

    # Make the API call
    headers = {'apiKey': API_KEYS._NVD_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch data from NVD: {response.status_code} - {response.text}")

    # Parse the response and create CVE objects
    cve_list = []
    data = response.json()
    for item in data.get('result', {}).get('CVE_Items', []):
        cve_id = item['cve']['CVE_data_meta']['ID']
        description = item['cve']['description']['description_data'][0]['value']
        severity = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
        vector_string = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('attackVector', 'UNKNOWN')
        complexity = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('attackComplexity', 'UNKNOWN')
        privileges_required = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('privilegesRequired', 'UNKNOWN')
        user_interaction = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('userInteraction', 'UNKNOWN')
        confidentiality_impact = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('confidentialityImpact', 'UNKNOWN')
        integrity_impact = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('integrityImpact', 'UNKNOWN')
        availability_impact = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('availabilityImpact', 'UNKNOWN')

        # Initialize the CVE object with the new attributes
        cve_obj = CVE(cve_id, description, severity, vector_string, complexity, privileges_required, 
                      user_interaction, confidentiality_impact, integrity_impact, availability_impact)
        cve_list.append(cve_obj)

    return cve_list

cveList = check_nvd(1)
print(len(cveList))