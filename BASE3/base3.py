import json
import re
from openai import OpenAI, OpenAIError
import logging
import httpx
import os
logging.getLogger("neo4j").setLevel(logging.ERROR)
http_client = httpx.Client(verify=False)
class Run():
    def __init__(self):
        self.client = OpenAI(
            base_url="",
            api_key=os.getenv("OPENAI_API_KEY", "your api key"),
            http_client=http_client,
        )
    
    def save_messages_to_json(self,filename,messages):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(messages, f, ensure_ascii=False, indent=4)
    
    def run_LLM(self,json_file):
        
        with open(json_file, "r") as f:
            datas = json.load(f)
        i=0
        for data in datas:
            i=i+1
            print("Entry {}".format(i))
            messages=[]
            code=data['function_code']
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
            self.chat_with_pirate(messages)
            response1=messages[-1]['content']
            print(messages[-1]['content'])
            data['predict']=response1
            if  "True" in response1:
                user_input=f"In your previous response, the code contains vulnerabilities. But the code might include security measures to address it. Re-evaluate and reply only with True (if a vulnerability exists) or False, without any further explanation."
                messages.append({"role": "user", "content": user_input})
                self.chat_with_pirate(messages)
                response2=messages[-1]['content']
                data['predict']=response2
                print("Second judgment: {}".format(data['predict']))                              
                        
        self.save_messages_to_json('KGVD/BASE3/result/CWE119/grok/function/base3.json',datas)
        
    def chat_with_pirate(self,messages):
        response =self.client.chat.completions.create(
            model="grok-3-mini",
            messages=messages
        )
        response_content = response.choices[0].message.content
        messages.append({"role": "assistant", "content": response_content})


run1 =Run()
run1.run_LLM("data_119.json")
