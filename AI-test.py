import base64
import vertexai
from vertexai.generative_models import GenerativeModel, Part, SafetySetting
import google.auth

"""
credentials, project_id = google.auth.default()
print(f"Credentials: {credentials}")
print(f"Project ID: {project_id}")
"""

def generate():
    vertexai.init(project="peter-test-2024", location="us-central1")
    model = GenerativeModel(
        "gemini-1.5-pro-001",
    )
    responses = model.generate_content(
        [Question_to_AI],
        generation_config=generation_config,
        safety_settings=safety_settings,
        stream=True,
    )

    for response in responses:
        print(response.text, end="")

user_input = input("Please enter question: ")
Question_to_AI = """The answer must be SQL command or a bash script to be executed without any explanation or comments. Just a script to be executed as it is for testing""" + user_input 

#Question_to_AI = """Provide a comprehensive overview of  in database security.  Include key concepts, best practices, common threats, mitigation strategies, relevant technologies, and industry standards.  Explain the topic in detail, offering practical examples where applicable.  If the topic is too broad, focus on the most critical aspects and suggest further areas for exploration."""

generation_config = {
    "max_output_tokens": 8192,
    "temperature": 1,
    "top_p": 0.95,
}

safety_settings = [
    SafetySetting(
        category=SafetySetting.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=SafetySetting.HarmBlockThreshold.OFF
    ),
    SafetySetting(
        category=SafetySetting.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=SafetySetting.HarmBlockThreshold.OFF
    ),
    SafetySetting(
        category=SafetySetting.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=SafetySetting.HarmBlockThreshold.OFF
    ),
    SafetySetting(
        category=SafetySetting.HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=SafetySetting.HarmBlockThreshold.OFF
    ),
]

generate()