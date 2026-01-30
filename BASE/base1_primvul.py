import json
from openai import OpenAI, OpenAIError
import time
import httpx
import os


client = OpenAI(
    base_url="",
    api_key=os.getenv("OPENAI_API_KEY", ""),
)

def run_LLM(json_file):
    try:
        datas = []
        with open(json_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    datas.append(json.loads(line))
    except Exception as e:
        print(f"Failed to load JSON file: {json_file}. Error: {e}")
        return
    i=0
    for data in datas:
        i=i+1
        if i % 5 == 0:
            time.sleep(1)  
        print("Entry {}".format(i))
        code=data['func']
        messages=[]
        messages = [
            {"role": "system", "content": "You are a vulnerability detection expert."},
            {"role": "user", "content": f"""
                Given the following code, please detect whether there is a vulnerability in the code snippet
                Code Snippet:
                '''
                {code}
                '''
                  Provide your response in exactly the following format:
                    {{
                        "Vulnerability_Present?": "True or False"
                    }}

            Do not include any explanation or additional information.
            """}
        ]

        response = client.chat.completions.create(
            model="claude-3-5-sonnet-20240620",
            messages=messages
        )
        
        response_content = response.choices[0].message.content
        print(response_content)
        data['predict']=response_content

   
    with open("KGVD/BASE/result/CWE119/claude/function/base1_primevul.json", "w", encoding="utf-8") as f:
        json.dump(datas, f, ensure_ascii=False, indent=4)
    print("Results saved to result.json")

if __name__ == "__main__":
    run_LLM("primevul_CWE-119.jsonl")
