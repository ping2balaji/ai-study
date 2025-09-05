#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

client = OpenAI()

messages = [{"role":"user", "content":"hello!"}]
response = client.chat.completions.create(model="gpt-4o-mini", messages=messages)

print(response.choices[0].message.content)

