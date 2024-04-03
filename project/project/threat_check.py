from project import *

db = setup_db()
new_cves = check_nvd(30)
# print(f"Number of new cves captured: {len(new_cves)}")
# update_cves_table(new_cves, db)
# # print_table(db, 'cves')
# db.close()