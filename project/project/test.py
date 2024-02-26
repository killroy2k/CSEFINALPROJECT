from cvss import CVSS4



#check cvss 4.0 test code to see its functionality
vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
c = CVSS4(vector)
print(vector)
print(c.base_score)
print(c.severity)

def caculate_cvss_score(vector):
    c = CVSS4(vector)
    return c.base_score

def caculate_cvss_severity(vector):
    c = CVSS4(vector)
    return c.severity
