from cvsslib import cvss31, calculate_vector

vector_v3 = "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H"
print(calculate_vector(vector_v3, cvss31))



def calculate_cvss_score_v31(vector):
    return calculate_vector(vector, cvss31) #returns a tuple with the base score, temporal score and environmental score


result = calculate_cvss_score_v31(vector_v3)
print(result)
print(result[0]) #base score


#fuck my life