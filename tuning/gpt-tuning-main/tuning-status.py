import os
import openai
from time import sleep
# from dotenv import load_dotenv

# load_dotenv()
openai.api_key = "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"

job_id = 'ftjob-kVyB3YLVa0iR5egHNQllYitz'
while True:
    res = openai.fine_tuning.jobs.retrieve(job_id)
    if res.finished_at != None:
        break
    else:
        print(".", end="")
        sleep(100)
ft_model = res.fine_tuned_model
print(ft_model)

"""ft:gpt-3.5-turbo-0613:personal::85Joy8Y6"""
