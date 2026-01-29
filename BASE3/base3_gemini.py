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
            # gpt-5
            base_url="https://api.gptsapi.net/v1",
            api_key=os.getenv("OPENAI_API_KEY", "sk-VbP0e2cb43247229a172e9e352a9813e20d606afd79uJG5s"),
            http_client=http_client,
            # api_key="sk-28ea529252a64b279a4111e1bb00cda3", # 如果您没有配置环境变量，请在此处用您的API Key进行替换
            # base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # 填写DashScope服务的base_url
            # api_key="sk-eb5e53e9453441d5b87b340ea678c872",
            # base_url="https://api.deepseek.com",
            # base_url="https://qianfan.baidubce.com/v2/",
            # api_key="bce-v3/ALTAK-KLlpJG3Dta1r3b2KNy7Fc/f0acebc92fc47092a16357bd99f1df01e11dce72"
            # api_key="ABCD",
            # base_url="http://222.20.126.168:8000/v1", 
                # base_url="http://222.20.126.169:8000/v1"
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
            print("第{}条".format(i))
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
                user_input=f"In your previous response, the code contains vulnerabilities; however, it may incorporate security measures to mitigate them. Please re-evaluate and respond solely with True (if a vulnerability exists) or False (if no vulnerability exists), without additional explanation."
                messages.append({"role": "user", "content": user_input})
                self.chat_with_pirate(messages)
                response2=messages[-1]['content']
                data['predict']=response2
                print("二次判断：{}".format(data['predict']))                              
                        
        self.save_messages_to_json('/home/nfs/d2024-lhq/lhq/KGVD/BASE3/result/CWE119/gemini/function/base3.json',datas)
        
    def chat_with_pirate(self,messages):
        #llama3
        response =self.client.chat.completions.create(
            # model="grok-3-mini",
            # model = "/models",
            # model="claude-3-5-sonnet-20240620",
            # model="deepseek-reasoner",
             model="gemini-2.5-flash",
            # model="ernie-4.5-turbo-128k",
            # max_tokens=200,
            # stream=True,
            # temperature=0.5,
            # model="o4-mini",
            messages=messages
        )
        response_content = response.choices[0].message.content
        # Add the model's response to messages
        messages.append({"role": "assistant", "content": response_content})


run1 =Run()
run1.run_LLM("data_119.json")

# deepseek-chat
# Precision: 0.4359
# Recall: 0.6733
# F1 Score: 0.5292
# Accuracy: 0.4010

# qwen-coder-32b
# Precision: 0.4144
# Recall: 0.4554
# F1 Score: 0.4340
# Accuracy: 0.4059

# CWE119 deepseek-chat
# Precision: 0.6111
# Recall: 0.7719
# F1 Score: 0.6822
# Accuracy: 0.6204

# qwen-coder
# Precision: 0.6604
# Recall: 0.6140
# F1 Score: 0.6364
# Accuracy: 0.6296

# KG问题
# 对于补丁中只有新加入的变量，无法处理

# deepseek温度必须0.5