
from google import genai
from google.genai import types

client = genai.Client(
    vertexai=True,
    project="gen-lang-client-0799569470",
    location="us-central1"
)

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Is this URL suspicious? https://cheapworldcuptickets2026.com — answer in one sentence."
)

print(response.text)
