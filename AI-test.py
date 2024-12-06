import base64
import vertexai
from vertexai.generative_models import GenerativeModel, Part, SafetySetting
import google.auth

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
Question_to_AI = """The answer must be SQL command or a bash script to be executed without any explanation or comments. 
Just a script to be executed as it is for testing. The database engine version is Oracle database version 23""" + user_input 

generation_config = {
    "max_output_tokens": 2000,
    "temperature": 2,
    "top_p": 0.5,
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