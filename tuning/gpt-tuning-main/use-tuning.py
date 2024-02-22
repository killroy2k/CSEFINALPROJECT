import os
import openai
from dotenv import load_dotenv
load_dotenv()
openai.api_key = os.getenv('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') # Set the API key

completion = openai.ChatCompletion.create( # Create a chat completion
  model="ft:gpt-3.5-turbo-0613:personal::85Joy8Y6", # Use the fine-tuned model
  messages=[ # Provide the messages to the model
    {"role": "system", "content": "You are a helpful AI assistant. You're given a text and answer who will be cyber attack by who, when, and by which way."},
    {"role": "user", "content": "A new ransomware called NWRansomware has recently surfaced on underground channels. It is constructed with a C++ client and a Python server, primarily aimed at Windows operating systems. This ransomware employs AES encryption, and it features a command-line interface (CLI) for conducting ransom negotiations."}
  ],
  temperature = 1 # Set the temperature to 1
)
print(completion.choices[0].message) # Output: "The ransomware is likely to target Windows operating systems. It is constructed with a C++ client and a Python server, and it employs AES encryption. It features a command-line interface (CLI) for conducting ransom negotiations."
