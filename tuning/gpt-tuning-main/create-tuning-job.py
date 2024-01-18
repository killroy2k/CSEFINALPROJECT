import os
import openai
from dotenv import load_dotenv
load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

#https://www.pinecone.io/learn/fine-tune-gpt-3.5

res = openai.FineTuningJob.create(
    training_file='file-6QG5cJlXiM2AhHvb59kI26n8',
    model="gpt-3.5-turbo"
)
job_id = res["id"]
print(res)

"""{
  "object": "fine_tuning.job",
  "id": "ftjob-D9BoPIKpl1Ex0b86I05WTm8C",
  "model": "gpt-3.5-turbo-0613",
  "created_at": 1696278143,
  "finished_at": null,
  "fine_tuned_model": null,
  "organization_id": "org-BLbVYlq3RPNUXhzZuyCN0qOJ",
  "result_files": [],
  "status": "validating_files",
  "validation_file": null,
  "training_file": "file-6QG5cJlXiM2AhHvb59kI26n8",
  "hyperparameters": {
    "n_epochs": "auto"
  },
  "trained_tokens": null,
  "error": null
}"""
