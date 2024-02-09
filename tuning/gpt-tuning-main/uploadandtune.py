import os
import openai
from dotenv import load_dotenv
from time import sleep

load_dotenv()
openai.api_key = os.getenv('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')

res = openai.File.create(
  file=open("./dataset/mydata_4.jsonl", "rb"),
  purpose='fine-tune'
)

file_id = res["id"]
print("file id is: ", file_id)

res = openai.FineTuningJob.create(
    training_file=file_id,
    model="gpt-3.5-turbo"
)
job_id = res["id"]
print("job id is: ",res)

while True:
    res = openai.FineTuningJob.retrieve(job_id)
    if res["finished_at"] != None:
        break
    else:
        print(".", end="")
        sleep(100)
ft_model = res["fine_tuned_model"]
print("model is: ",ft_model)
