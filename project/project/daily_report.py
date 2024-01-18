from project import *

db = setup_db()
check_cisa(db, 1)
print(send_report_mail(db))
db.close()