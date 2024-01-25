from project import *

db = setup_db()
check_cisa(db, 7)
print(send_report_mail(db))
db.close()