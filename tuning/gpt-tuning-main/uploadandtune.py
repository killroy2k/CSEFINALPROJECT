import os
from openai import OpenAI
from dotenv import load_dotenv
from time import sleep

client = OpenAI()  # Create an OpenAI client

load_dotenv() # Load the environment variables
client.api_key = os.getenv('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') # Set the API key

res = client.file.create( # Upload the file to OpenAI
  file=open("./dataset/mydata_4.jsonl", "rb"), # Use the file for fine-tuning
  purpose='fine-tune' # Use the file for fine-tuning
) # Upload the file to OpenAI

file_id = res["id"] # Get the file id
print("file id is: ", file_id) # Print the file id

res = client.FineTuningJob.create( # Create a fine-tuning job
    training_file=file_id, # Use the file id to specify the training file
    model="gpt-3.5-turbo" # Use the gpt-3.5-turbo model
)# Create a fine-tuning job

job_id = res["id"] # Get the job id
print("job id is: ",res) # Print the job id

while True: # Wait for the fine-tuning job to finish
    res = client.FineTuningJob.retrieve(job_id) # Get the fine-tuning job
    if res["finished_at"] != None: # If the job is finished,
        break # break the loop
    else: # If the job is not finished,
        print(".", end="") # print a dot
        sleep(100) # wait for 100 seconds
ft_model = res["fine_tuned_model"] # Get the fine-tuned model
print("model is: ",ft_model) # Print the fine-tuned model
