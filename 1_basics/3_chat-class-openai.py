#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from openai import OpenAI
import json

load_dotenv(override=True)

class chatSession():
    def __init__(self, client=None, systemPrompt="You are a helpful assistant"):
        self.model = "gpt-4.1-nano"
        self.client = OpenAI()
        self.systemPrompt = systemPrompt
        self.messages = [{"role":"system", "content":systemPrompt}]

    def chat(self, message: str):
        self.messages.append({"role":"user", "content":message})
        print("User Question = ", message)
        response = self.client.chat.completions.create(model=self.model, messages=self.messages)
        answer = response.choices[0].message.content
        print("Assistant Answer = ", answer)
        self.messages.append({"role":"assistant", "content": answer})
        return answer


# client = OpenAI()
# session = chatSession(client=client)
session = chatSession()
session.chat("hi there, my name is 2chatsession")
session.chat("do you know my name")
