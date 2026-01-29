import os

def process(input,output):
    import json
    Result = []
    with open(input, "r", encoding="utf-8") as f:
        data = json.load(f)
    for i in data:
        predict_str = str(i['predict']).strip()
        is_positive = "True" in predict_str or "true" in predict_str.lower()
        
        Result.append({
            "label": i.get('label', i.get('target', 0)),
            "predict": 1 if is_positive else 0
        })
 
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(Result, f, ensure_ascii=False, indent=4)

def caculate(input):
    from sklearn.metrics import f1_score,precision_score,recall_score,accuracy_score
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
    accuracy = accuracy_score(y_true, y_pred)

    print(f"Precision: {precision:.4f}")  
    print(f"Recall: {recall:.4f}")       
    print(f"F1 Score: {f1:.4f}")         
    print(f"Accuracy: {accuracy:.4f}")

base_path = "KGVD/result/CWE119"
model_name = "grok"

input_file = os.path.join(base_path, model_name, "function", "KGVD2_primevul.json")
output_file = os.path.join(base_path, model_name, "function", "KGVD2_primevul_.json")

process(input_file, output_file)
caculate(output_file)


