#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from openai import OpenAI
import json

load_dotenv(override=True)
model = "gpt-4.1-nano"
client = OpenAI()

# 1st query
messages = [{"role":"user", "content":"hello! my name is helloworld-user!"}]
response = client.chat.completions.create(model=model, messages=messages)
#print(response.choices[0].message)
answer = response.choices[0].message.content

# without appending above assistant response in the next chat question,
# LLM cannot tell your name eventhough you have sent the same in previous chat.
# Comment/Uncomment below line and clear "messages" array to check the difference. 
# This is called chat/session memory!
messages.append({"role":"assistant", "content": answer})

# 2nd query
#messages = []
messages.append({"role":"user", "content": "do you know my name"})

print(f"Request sent: " , json.dumps(messages))

response = client.chat.completions.create(model=model, messages=messages)
answer = response.choices[0].message.content

print(answer)