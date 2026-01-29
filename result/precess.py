import os

def process(input,output):
    import json
    Result = []
    with open(input, "r", encoding="utf-8") as f:  # 添加文件打开模式 "r" 和编码
        data = json.load(f)
    for i in data:
        # 处理predict字段：可能是字符串"True"/"False"，或包含JSON的字符串
        predict_str = str(i['predict']).strip()
        # 检查是否包含"True"（不区分大小写）
        # 注意："False"不包含"True"，所以这个判断是安全的
        is_positive = "True" in predict_str or "true" in predict_str.lower()
        
        Result.append({
            # "cve": i['cve'],
            # "key_value": i['key_value'],
            # "key_value_type": i['key_value_type'],
            "label": i.get('label', i.get('target', 0)),  # 兼容label和target字段
            # "kg_node": i["kg_node"],  # 修正 i[kg_node] 为 i["kg_node"]
            "predict": 1 if is_positive else 0
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
    precision = precision_score(y_true, y_pred,pos_label=1)
    recall = recall_score(y_true, y_pred,pos_label=1)
    f1 = f1_score(y_true, y_pred,pos_label=1)
    balanced_accuracy = balanced_accuracy_score(y_true, y_pred)
    mcc = matthews_corrcoef(y_true, y_pred)  # 避免变量名遮蔽函数名
    accuracy = accuracy_score(y_true, y_pred)

    print(f"Precision: {precision:.4f}")  
    print(f"Recall: {recall:.4f}")       
    print(f"F1 Score: {f1:.4f}")         
    print(f"Accuracy: {accuracy:.4f}")  
    print(f"Balanced Accuracy: {balanced_accuracy:.4f}")
    print(f"Matthews Correlation Coefficient: {mcc:.4f}")
# 基础路径配置
base_path = "/home/nfs/d2024-lhq/lhq/KGVD/result/CWE119"
model_name = "grok"  # 可以改成其他模型名称，如 "GPT", "Llama" 等

# 构建输入和输出路径
input_file = os.path.join(base_path, model_name, "function", "KGVD2_primevul.json")
output_file = os.path.join(base_path, model_name, "function", "KGVD2_primevul_.json")

process(input_file, output_file)
caculate(output_file)


