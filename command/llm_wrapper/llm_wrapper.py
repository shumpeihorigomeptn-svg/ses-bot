import os

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv(".env")

OPENAI_API_KEY=os.getenv("OPENAI_API_KEY")

class LLMAPI:
    
    def __init__(self):
        self.api_key = OPENAI_API_KEY

    def request_openai(self, messages: list):
        client = OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            messages = messages,
            model="gpt-5-mini",
        )
        return response.choices[0].message.content