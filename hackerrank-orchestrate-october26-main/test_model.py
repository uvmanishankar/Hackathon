import os
from groq import Groq

client = Groq(api_key=os.environ["GROQ_API_KEY"])
big = "x " * 500  # ~1000 tokens input
resp = client.chat.completions.create(
    model="qwen/qwen3.8-27b",
    messages=[
        {"role": "system", "content": big},
        {"role": "user", "content": 'Output only: {"deletion_status":"COMPLETE","steps":[]}'}
    ],
    temperature=0,
    max_tokens=50
)
usage = resp.usage
print("Tokens used:", usage.total_tokens if usage else "n/a")
print("Response:", repr(resp.choices[0].message.content[:80]))
