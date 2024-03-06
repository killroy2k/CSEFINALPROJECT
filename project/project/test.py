from cvss import CVSS3,CVSS4


# vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
# c = CVSS3(vector)
# print(c.scores()[0])

# #check cvss 4.0 test code to see its functionality
# vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
# c = CVSS4(vector)
# print(vector)
# print(c.base_score)
# print(c.severity)

# def caculate_cvss_score(vector):
#     c = CVSS4(vector)
#     return c.base_score

# def caculate_cvss_severity(vector):
#     c = CVSS4(vector)
#     return c.severity


vector = "network/adjacent: network/ac: low/pr: none/ui: none/s: unchanged/c: none/i: none/a: none"
c = vector.split("/")
print(c)

good = "av:n/ac:l/pr:n/ui:n/s:c/c:n/i:n/a:h"
print(len(good))
print(len(vector))