from project import *

db = setup_db()
new_cves = check_nvd(30)
print(f"Number of new cves captured: {len(new_cves)}")
update_cves_table(new_cves, db,debug=True)
# print_table(db, 'cves')
db.close()


# f = io.StringIO()

# with redirect_stdout(f):
#     db = setup_db()
#     new_cves = check_nvd(30)
#     update_cves_table(new_cves, db, debug=True)
#     print_table(db, 'cves')
#     db.close()

# out = f.getvalue()

# with open('debug_log.txt', 'w') as file:
#     file.write(out)

# file.close()