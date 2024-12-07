import base64
import vertexai
from vertexai.generative_models import GenerativeModel, Part, SafetySetting
import google.auth
import csv
import os


#Generates SQL command or script based on the given question using Vertex AI.
def generate_sql(question):
   
    vertexai.init(project="peter-test-2024", location="us-central1")
    
    # Use one of the AI Models "gemini-1.5-pro-001"
    model = GenerativeModel("gemini-1.5-pro-001")
    
    # Add to the question the text which to try forcing the AI to generate SQL
    Question_to_AI = (
        "The answer must be SQL command or a bash script to be executed without any explanation or comments. "
        "Just a script to be executed as it is for testing. Database engine version is Oracle database version 23. "
        + question
    )
    
    # Generation configuration
    generation_config = {
        "max_output_tokens": 2000,
        "temperature": 2,
        "top_p": 0.5,
    }
    
    # Generate content
    responses = model.generate_content(
        [Question_to_AI],
        generation_config=generation_config,
        safety_settings=safety_settings,
        stream=True,
    )
    result = ""
    for response in responses:
        result += response.text
    return result.strip()

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

def main():
    input_file_path = input("Enter the path to your input CSV file: ")
    
    # Determine the directory of the input file and create the output file path
    input_dir = os.path.dirname(input_file_path)
    output_file_name = "output.sql"  # Default output file name
    output_file_path = os.path.join(input_dir, output_file_name)
    
    print(f"The output file will be saved at: {output_file_path}")

    try:
        with open(input_file_path, 'r') as csvfile, open(output_file_path, 'w') as sqlfile:
            reader = csv.reader(csvfile)
            for i, row in enumerate(reader, start=1):
                if not row:  # Skip empty rows
                    continue
                try:
                    question = row[0]
                    print(f"Processing row {i}: {question}")
                    sql_output = generate_sql(question)
                    sqlfile.write(sql_output + '\n\n')
                except Exception as e:
                    print(f"Error processing row {i}: {e}")
    except FileNotFoundError:
        print("The specified input file was not found.")
    except IOError as e:
        print(f"An I/O error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
    
    