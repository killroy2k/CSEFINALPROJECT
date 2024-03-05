import os
import openai
# from dotenv import load_dotenv
# load_dotenv()
openai.api_key = "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"

res = openai.files.create(
  file=open("dataset/NewTuningData.jsonl", "rb"),
  purpose='fine-tune'
)

file_id = res.id
print("id is: ", file_id)
print("status: ", res.status)
