import os
def process(input,output):
    j=1
    k=1
    import json
    Result = []
    with open(input, "r", encoding="utf-8") as f:  # 添加文件打开模式 "r" 和编码
        data = json.load(f)
    for i in data:
        if "True" in i['predict']:  # 缩进正确
            j=j+1
            Result.append({
                # "cve": i['cve'],
                # "key_value": i['key_value'],
                # "key_value_type": i['key_value_type'],
                "label": i['label'],
                # "kg_node": i["kg_node"],  # 修正 i[kg_node] 为 i["kg_node"]
                "predict": "True"
            })
        else:
            k=k+1
            Result.append({
                # "cve": i['cve'],
                # "key_value": i['key_value'],
                # "key_value_type": i['key_value_type'],
                "label": i['label'],
                # "kg_node": i["kg_node"],  # 修正 i[kg_node] 为 i["kg_node"]
                "predict": "False"
            })
 
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(Result, f, ensure_ascii=False, indent=4)

def caculate(input):
    from sklearn.metrics import f1_score,precision_score,recall_score,accuracy_score,balanced_accuracy_score,matthews_corrcoef
    import json
    y_true=[]
    y_pred=[]
    with open(input) as f:
        datas=json.load(f)
    for i in datas:
        y_true.append(i['label'])
        y_pred.append(i['predict'])  
    precision = precision_score(y_true, y_pred,pos_label='True')
    recall = recall_score(y_true, y_pred,pos_label='True')
    f1 = f1_score(y_true, y_pred,pos_label='True')
    balanced_accuracy = balanced_accuracy_score(y_true, y_pred)
    matthews_corrcoef = matthews_corrcoef(y_true, y_pred)
    accuracy = accuracy_score(y_true, y_pred)

    print(f"Precision: {precision:.4f}")  
    print(f"Recall: {recall:.4f}")       
    print(f"F1 Score: {f1:.4f}")         
    print(f"Accuracy: {accuracy:.4f}")  
    print(f"Balanced Accuracy: {balanced_accuracy:.4f}")
    print(f"Matthews Correlation Coefficient: {matthews_corrcoef:.4f}") 
# 基础路径配置
base_path = "/home/nfs/d2024-lhq/lhq/KGVD/BASE3/result/CWE119"
model_name = "gemini"  # 可以改成其他模型名称，如 "Qwen", "Llama" 等

# 构建输入和输出路径
input_file = os.path.join(base_path, model_name, "function", "base3.json")
output_file = os.path.join(base_path, model_name, "function", "base3_.json")

process(input_file, output_file)
caculate(output_file)

# deepseek-reasoner 提升不大
# grok o4mini claude gemini