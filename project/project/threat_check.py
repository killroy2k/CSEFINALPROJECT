from project import *

db = setup_db()
new_cves = check_nvd(1)
print(f"Number of new cves captured: {len(new_cves)}")
update_cves_table(new_cves, db,debug=True)
# print_table(db, 'cves')
db.close()