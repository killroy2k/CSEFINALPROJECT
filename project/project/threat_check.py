from project import *
import io
import json
from contextlib import redirect_stdout

f = io.StringIO()

with redirect_stdout(f):
    db = setup_db()
    new_cves = check_nvd(30)
    update_cves_table(new_cves, db, debug=True)
    print_table(db, 'cves')
    db.close()

out = f.getvalue()

##THE CODE BELOW IS FOR DEBUGGING PURPOSES##


# run the code below to create the debug_log.txt file in the project folder
#            which you can then copy the path for the task scheduler to output to the file in the project folder
# with open('debug_log.txt', 'w') as file:

# code with the path to the file in project folder for task scheduler
# to copy path right click on the file and copy the path and paste it in the code below

## IF THE PATH USES FORWARD SLASHES (\), MAKE SURE TO CHANGE THEM TO BACKSLASHES (/) ##
with open('C:/Users/Vynze/OneDrive - University of South Florida/Documents/GitHub/CSEFINALPROJECT/project/project/debug_log.txt', 'w') as file:
    file.write(out)
