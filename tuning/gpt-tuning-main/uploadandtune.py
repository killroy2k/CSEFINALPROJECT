import os
from openai import OpenAI
from dotenv import load_dotenv
from time import sleep

client = OpenAI() # Initialize the OpenAI client

load_dotenv()
client.api_key = os.getenv('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')

client.file.create(
  file=open("./dataset/mydata_4.jsonl", "rb"),
  purpose='fine-tune'
) # Upload the file to OpenAI

#ile_id = res["id"]
#print("file id is: ", file_id) 

# res = client.FineTuningJob.create(
#     training_file=file_id,
#     model="gpt-3.5-turbo"
# )

#job_id = res["id"]
#print("job id is: ",res)

# while True:
#     res = client.FineTuningJob.retrieve(job_id)
#     if res["finished_at"] != None:
#         break
#     else:
#         print(".", end="")
#         sleep(100)
# ft_model = res["fine_tuned_model"]
# print("model is: ",ft_model)
