import os
import json
import mimetypes

from dotenv import load_dotenv
from google import genai


load_dotenv()

_client = None


def _get_client():
    """Create the Gemini client on first use, so the web app can still boot
    (lock screen, health check) if GEMINI_API_KEY is missing. The key comes
    from the environment only and is never sent to the browser."""
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set on the server")
        _client = genai.Client(api_key=api_key)
    return _client


def analyze_text(text):
    prompt = f"""
You are an evidence organization assistant for SafeVault.

Analyze the following fictional evidence.

Return ONLY valid JSON with exactly these fields:

{{
    "category": "one of: Threat, Harassment, Physical Abuse, Financial Abuse, Stalking, Other",
    "severity": "one of: Low, Medium, High, Critical",
    "summary": "a short factual summary",
    "incident_date": "YYYY-MM-DD if a date is mentioned, otherwise null"
}}

Do not add markdown.
Do not add explanations.

Evidence:
{text}
"""

    response = _get_client().models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
    )

    return json.loads(response.text)


def analyze_image(image_path):
    prompt = """
You are an evidence organization assistant for SafeVault.

Analyze the uploaded image as fictional evidence.

Look for:
- Threats
- Harassment
- Physical abuse
- Financial abuse
- Stalking
- Other relevant evidence
- Any date visible in the image
- Important factual details

Return ONLY valid JSON with exactly these fields:

{
    "category": "one of: Threat, Harassment, Physical Abuse, Financial Abuse, Stalking, Other",
    "severity": "one of: Low, Medium, High, Critical",
    "summary": "a short factual summary of what the image shows",
    "incident_date": "YYYY-MM-DD if a date is visible or clearly stated, otherwise null"
}

Do not add markdown.
Do not add explanations.
"""

    mime_type, _ = mimetypes.guess_type(image_path)

    if mime_type not in ["image/png", "image/jpeg", "image/webp"]:
        mime_type = "image/png"

    with open(image_path, "rb") as image_file:
        image_data = image_file.read()

    response = _get_client().models.generate_content(
        model="gemini-3.5-flash",
        contents=[
            prompt,
            genai.types.Part.from_bytes(
                data=image_data,
                mime_type=mime_type
            )
        ],
    )

    return json.loads(response.text)


if __name__ == "__main__":

    test_text = """
    On October 5, 2026, the person threatened me through text messages
    and said that they would hurt me if they contacted anyone.
    """

    result = analyze_text(test_text)

    print("\n--- STRUCTURED GEMINI ANALYSIS ---")
    print(json.dumps(result, indent=4))