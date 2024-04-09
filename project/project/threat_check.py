from project import *

# db = setup_db()
# new_cves = check_nvd(30)
# print(f"Number of new cves captured: {len(new_cves)}")
# update_cves_table(new_cves, db,debug=True)
# # print_table(db, 'cves')
# db.close()
import io
import json
from contextlib import redirect_stdout

f = io.StringIO()

with redirect_stdout(f):
    db = setup_db()
    new_cves = check_nvd(60)
    update_cves_table(new_cves, db, debug=True)
    print_table(db, 'cves')
    db.close()

out = f.getvalue()

with open('debug_log.txt', 'w') as file:
    file.write(out)


with open('debug.json', 'w') as file:
    out = str(out).replace('\n', ' ')
    json.dump(out, file, indent=4)
