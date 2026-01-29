import os

def process(input,output):
    j=1
    k=1
    import json
    Result = []
    with open(input, "r", encoding="utf-8") as f:
        data = json.load(f)
    for i in data:
        if "True" in i['predict']:
            j=j+1
            Result.append({
                "label": i['label'],
                "predict": "True"
            })
        else:
            k=k+1
            Result.append({
                "label": i['label'],
                "predict": "False"
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
    precision = precision_score(y_true, y_pred,pos_label="True")
    recall = recall_score(y_true, y_pred,pos_label="True")
    f1 = f1_score(y_true, y_pred,pos_label="True")
    accuracy = accuracy_score(y_true, y_pred)

    print(f"Precision: {precision:.4f}")  
    print(f"Recall: {recall:.4f}")       
    print(f"F1 Score: {f1:.4f}")         
    print(f"Accuracy: {accuracy:.4f}")  

base_path = "KGVD/result/CWE119"
model_name = "claude"

input_file = os.path.join(base_path, model_name, "function", "KGVD2.json")
output_file = os.path.join(base_path, model_name, "function", "KGVD2_.json")

process(input_file, output_file)
caculate(output_file)


