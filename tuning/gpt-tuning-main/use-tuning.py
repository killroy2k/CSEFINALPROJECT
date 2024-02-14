import os
import openai
from dotenv import load_dotenv
load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

completion = openai.ChatCompletion.create(
  model="ft:gpt-3.5-turbo-0613:personal::85Joy8Y6",
  messages=[
    {"role": "system", "content": "You are a helpful AI assistant. You're given a text and answer who will be cyber attack by who, when, and by which way."},
    {"role": "user", "content": "A new ransomware called NWRansomware has recently surfaced on underground channels. It is constructed with a C++ client and a Python server, primarily aimed at Windows operating systems. This ransomware employs AES encryption, and it features a command-line interface (CLI) for conducting ransom negotiations."}
  ],
  temperature = 1
)
print(completion.choices[0].message)
