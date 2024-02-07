from project import *

db = setup_db()
db_response = check_cisa(db, 1)
print(db_response)
print(send_report_mail(db))
db.close()