import os
import openai
from dotenv import load_dotenv
load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

res = openai.File.create(
  file=open("mydata.jsonl", "rb"),
  purpose='fine-tune'
)

file_id = res["id"]
print("id is: ", file_id)
