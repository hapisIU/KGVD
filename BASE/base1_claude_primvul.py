import json
from openai import OpenAI, OpenAIError
import time
import httpx
import os
# logging.getLogger("neo4j").setLevel(logging.ERROR)
http_client = httpx.Client(verify=False)
# 初始化 OpenAI 客户端
# client = OpenAI(
#     api_key="ABCD",
#     base_url="http://222.20.126.168:8000/v1", 
# )


client = OpenAI(
    base_url="https://api.gptsapi.net/v1",
    api_key=os.getenv("OPENAI_API_KEY", "sk-VbP0e2cb43247229a172e9e352a9813e20d606afd79uJG5s"),
    http_client=http_client,
    # api_key="sk-eb5e53e9453441d5b87b340ea678c872",
    # base_url="https://api.deepseek.com",
    
    # base_url="https://qianfan.baidubce.com/v2",
    # api_key="bce-v3/ALTAK-KLlpJG3Dta1r3b2KNy7Fc/f0acebc92fc47092a16357bd99f1df01e11dce72"
    # api_key="ABCD",
    # base_url="http://222.20.126.169:8123/v1", 
)

def run_LLM(json_file):
    # 加载 JSON 文件（支持 JSONL 格式）
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
            time.sleep(1)  # 短暂休息
        print("第{}条".format(i))
        code=data['func']
        messages=[]
        # 构造消息
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

        # 发送 POST 请求
        response = client.chat.completions.create(
            # model="deepseek-chat",
            # model="grok-3-mini",
            # temperature=0.5,
            # model = "qwen3-coder-30b",#qwen
            # model="gpt-4o"
            # model="o4-mini",
            # model="gemini-2.5-flash",
            model="claude-3-5-sonnet-20240620",
            # model="deepseek-r1",
            # temperature=0.5,
            messages=messages
        )
        
        # 获取返回内容
        response_content = response.choices[0].message.content
        print(response_content)
        data['predict']=response_content

   
    with open("/home/nfs/d2024-lhq/lhq/KGVD/BASE/result/CWE119/claude/function/base1_primevul.json", "w", encoding="utf-8") as f:
        json.dump(datas, f, ensure_ascii=False, indent=4)
    print("Results saved to result.json")

# 示例调用
if __name__ == "__main__":
    # 调用函数
    run_LLM("primevul_CWE-119.jsonl")

# deepseek-chat
# Precision: 0.4106
# Recall: 0.6139
# F1 Score: 0.4921
# Accuracy: 0.3663

# qwen-coder
# Precision: 0.1481
# Recall: 0.0396
# F1 Score: 0.0625
# Accuracy: 0.4059

# CWE119 deepseek-chat
# Precision: 0.6230
# Recall: 0.6667
# F1 Score: 0.6441
# Accuracy: 0.6111

# qwen-coder
# Precision: 0.0000
# Recall: 0.0000
# F1 Score: 0.0000
# Accuracy: 0.4630