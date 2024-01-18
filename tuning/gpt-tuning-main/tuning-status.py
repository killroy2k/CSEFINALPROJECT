import os
import openai
from time import sleep
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

job_id = 'ftjob-D9BoPIKpl1Ex0b86I05WTm8C'
while True:
    res = openai.FineTuningJob.retrieve(job_id)
    if res["finished_at"] != None:
        break
    else:
        print(".", end="")
        sleep(100)
ft_model = res["fine_tuned_model"]
print(ft_model)

"""ft:gpt-3.5-turbo-0613:personal::85Joy8Y6"""
