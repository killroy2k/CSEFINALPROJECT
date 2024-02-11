import math


def RoundUp(value):
    rounded_up_value = value * 10
    rounded_up_value = math.ceil(rounded_up_value)
    rounded_up_value = rounded_up_value / 10
    return rounded_up_value

#scope == 0 == unchanged
#scope == 1 == changed

#Impact_conf (rest at 0.5675)
#ic:h =0.5675
#ic:l =0.234
#ic:n =0

#Impact_integ (rest at 0.5675)
#ii:h =0.5675
#ii:l =0.234
#ii:n =0

#Impact_avail (rest at 0.5675)
#ia:h =0.5675
#ia:l =0.234
#ia:n =0
def impact_score(scope, Impact_conf, Impact_integ, Impact_avail, exploitability):
    Impact_base = 1 - ((1-Impact_conf)*(1-Impact_integ)*(1-Impact_avail))
    
    if scope == 0:
        Impact_sub = 6.42 * Impact_base
        print("sub: ", Impact_sub)
        if Impact_sub < 0:
            return 0
        return RoundUp(min(Impact_sub + exploitability, 10))
    elif scope == 1:
        Impact_sub = (7.52 * (Impact_base - 0.029)) - (3.25 * ((Impact_base - 0.02) ** 15))
        print("sub: ", Impact_sub)
        if Impact_sub < 0:
            return 0
        return RoundUp(min(1.08 * (Impact_sub + exploitability), 10))

#all parameters are less than 1
#0.83 for all for baseline of 3.9
#so the values for each parameter are at most 0.83 or the total is 4 * 0.83

#attack vector (the rest at 0.83)
# av:n =0.83
# av:a =0.5959
# av:l =0.532
# av:p =0.1919
    
#attack complexity (the rest at 0.83)
#ac:l =0.83
# ac:h =0.47
    
#Privilege required (the rest at 0.83)
#pr:n =0.83
#pr:l =0.596
#pr:h =0.256
    
#user interaction (the rest at 0.83)
#ui:n =0.83
#ui:r =0.5959    
def exploitability_score(attack_vector, attack_complexity, Privilege_required, user_interaction):
    return 8.22 * attack_vector * attack_complexity * Privilege_required * user_interaction

exploit = exploitability_score(0.83, 0.47, 0.256, 0.83)
print("ex: ", exploit)
base = impact_score(0, 0.5675, 0.234, 0, exploit)
print("base: ", base)



#temporal and environmental scores are not used since most of the cves observed do not use these and finding the values for these is difficult


# def temporal_score(basescore, exploitcodematurity, remediationlevel, reportconfidence):
#     return RoundUp(basescore * exploitcodematurity * remediationlevel * reportconfidence)
#     return 0


# def enviromental_score(mscope, mattack_vector, mattack_complexity, mPrivilege_required, muser_interaction, mexploitcodematurity, mremediationlevel, mreportconfidence):
#     mexploitability = exploitability_score(mattack_vector, mattack_complexity, mPrivilege_required, muser_interaction)
#     mimpact_sub = impact_score(mscope, mexploitability)
#     modif_impact = temporal_score(mimpact_sub, mexploitcodematurity, mremediationlevel, mreportconfidence)
#     return 0