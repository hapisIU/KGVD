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
    # base_url="https://api.gptsapi.net/v1",
    # api_key=os.getenv("OPENAI_API_KEY", "sk-VbP0e2cb43247229a172e9e352a9813e20d606afd79uJG5s"),
    # http_client=http_client,
    api_key="sk-eb5e53e9453441d5b87b340ea678c872",
    base_url="https://api.deepseek.com",
    
    # base_url="https://qianfan.baidubce.com/v2",
    # api_key="bce-v3/ALTAK-KLlpJG3Dta1r3b2KNy7Fc/f0acebc92fc47092a16357bd99f1df01e11dce72"
    # api_key="ABCD",
    # base_url="http://222.20.126.169:8123/v1", 
)

def run_LLM(json_file):
    # 加载 JSON 文件
    try:
        with open(json_file, "r") as f:
            datas = json.load(f)
    except Exception as e:
        print(f"Failed to load JSON file: {json_file}. Error: {e}")
        return
    i=0
    for data in datas:
        i=i+1
        if i % 5 == 0:
            time.sleep(1)  # 短暂休息
        print("第{}条".format(i))
        code=data['function_code']
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

        # 发送 POST 请求（带重试机制）
        max_retries = 8  # 增加重试次数
        retry_delay = 3  # 增加初始延迟到3秒
        
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model="deepseek-chat",
                    # model="grok-3-mini",
                    temperature=0.5,
                    # model = "qwen3-coder-30b",#qwen
                    # model="gpt-4o"
                    # model="o4-mini",
                    # model="gemini-2.5-flash",
                    # model="claude-3-5-sonnet-20240620",
                    # model="deepseek-r1",
                    # temperature=0.5,
                    messages=messages
                )
                
                # 获取返回内容
                response_content = response.choices[0].message.content
                print(response_content)
                data['predict']=response_content
                time.sleep(0.5)  # 请求间隔，避免过快
                break  # 成功则退出循环
            except (OpenAIError, Exception) as e:
                error_str = str(e)
                # 判断是否是服务器负载错误（500错误）
                is_server_error = "500" in error_str or "saturated" in error_str or "InternalServerError" in str(type(e).__name__)
                
                if attempt < max_retries - 1:
                    # 指数退避：3秒, 6秒, 12秒, 24秒, 48秒, 96秒, 192秒, 384秒
                    wait_time = retry_delay * (2 ** attempt)
                    if is_server_error:
                        # 服务器错误时延迟更长（再翻倍）
                        wait_time = wait_time * 2
                    print(f"请求失败 (尝试 {attempt + 1}/{max_retries}): {error_str[:100]}")
                    print(f"等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    # 最后一次重试也失败了，保存错误信息并继续处理下一条
                    print(f"请求失败，已达最大重试次数，跳过本条数据: {error_str[:100]}")
                    data['predict'] = "Error: Max retries exceeded - " + error_str[:80]  # 保存错误信息
                    print(f"已保存错误信息，继续处理下一条数据...")
                    break  # 不抛出异常，继续处理下一条

   
    with open("/home/nfs/d2024-lhq/lhq/KGVD/BASE/result/CWE119/deepseek/function/base1.json", "w", encoding="utf-8") as f:
        json.dump(datas, f, ensure_ascii=False, indent=4)
    print("Results saved to result.json")

# 示例调用
if __name__ == "__main__":
    # 调用函数
    run_LLM("data_119.json")

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