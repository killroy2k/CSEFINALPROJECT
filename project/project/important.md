Make sure NVD API is 2.0 and check url
Twitter/X api is on basic subscription
Make sure openai api is also up to date

When running the commands, its either:

    python3 daily_report.py

    python3 threat_check.py

Resolved:

        fix get_cisa_accuracy
        somehow get an initial database for cisa
            fix the code so that it produces a fail on a new database


    Resolved: just had to change "cisa_accuracy" to "accuracy" under get_cisa_accuracy function on the line with cursor.execute


TO DO List:


    
    get james to message jeremy if he wants the last year project to work before working on the current proj requirements