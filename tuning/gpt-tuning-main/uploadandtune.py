import os
import openai
# from dotenv import load_dotenv
from time import sleep

# load_dotenv()
openai.api_key = "insert here"

res = openai.files.create(
  file=open("./dataset/NewTuningData.jsonl", "rb"),
  purpose='fine-tune'
)

file_id = res.id
print("file id is: ", file_id)

res = openai.fine_tuning.jobs.create(
    training_file=file_id,
    model="gpt-3.5-turbo"
)
job_id = res.id
print("job id is: ",res)

while True:
    res = openai.fine_tuning.jobs.retrieve(job_id)
    if res.finished_at != None:
        break
    else:
        print(".", end="")
        sleep(100)
ft_model = res.fine_tuned_model
print("model is: ",ft_model)
