import json
import re
from openai import OpenAI, OpenAIError
from connect import *
import logging
import httpx
import os
logging.getLogger("neo4j").setLevel(logging.ERROR)
http_client = httpx.Client(verify=False)
class Run():
    def __init__(self):
        self.type={
            'integer array':"integer array",
            'sp_cp':"struct pointer->char pointer", 
            'sp_integer':"struct->integer", 
            'char array':"char array", 
            'st.i':"struct.integer", 
            'sp_struct':"struct pointer->struct", 
            'integer pointer':"integer pointer", 
            'Integer':"Integer", 
            'char pointer':"char pointer", 
            'struct pointer':"struct pointer", 
            'pointer to pointer':"pointer to pointer", 
            "st.sp":"stuct.struct pointer"
        }
        self.fix_dict = {
        "reassign(+other fun)": "Reassign the key variable using another function",
        "update if(integer)": "Modify the conditional judgment for the key variable in the if statement",
        "update for(integer)": "Adjust the iteration condition of the for loop for the key variable",
        "replace(safe fun)": "Replace risky function with a secure alternative",
        "+fun(integer)": "Add a validation function for the key variable",
        "reassign(fun(integer))": "Reassign the key variable using a function",
        "+if(integer)": "Add conditional judgment for the key variable",
        "update(type(integer))": "Change the data type of the key variable",
        "+if(integer pointer)": "Add validation for the key variable",
        "if(update integer pointer)": "Add validation for the key variable",
        "+if(cp)": "Add conditional judgment for the key variable",
        "update if(cp)": "Modify the conditional logic for the key variable in the if statement",
        "reassign(new variable(integer))": "Introduce a new variable when reassigning the key variable",
        "+if(pp)": "Add conditional judgment for the key variable",
        "replace(other variable(sp))": "Substitute the key variable with another variable",
        "+if(sp)": "Add conditional validation for the key variable",
        "reassign(union.integer)": "Reassign the integer member of the union key variable directly",
        "update calculate": "Modify the calculation logic for the key variable",
        "+if(struct.integer)": "Add validation for the integer member of a struct key variable",
        "reassign(other variable(sp))": "Reassign the key variable using another variable",
        "replace(new variable(integer))": "Substitute the key variable with a new variable",
        "update len(array)": "Adjust the array length for the key variable",
        "+if(char array)": "Add validation for the array key variable",
        "reassign(other variable)": "Reassign the key variable using another variable",
        "+if(other variable)": "Add conditional logic for other variable in the code",
        "replace(other variable(struct pointer))": "Replace the key variable with another variable",
        "update if(sp_integer)": "Modify the pointer validation logic for the key variable",
        "replace(fun)": "Replace the current function with an alternative",
        "+if(sp_integer)": "Add validation for the key variable",
        "update for(cp)": "Modify the for loop iteration condition for the key variable",
        "update while(integer)": "Adjust the while loop termination condition for the key variable",
        "+if(sp_sp)": "Add validation for the key variable",
        "update if(sp_sp)": "Modify the conditional validation logic for the key variable",
        "+if(sp_cp)": "Add validation for the key variable",
        "+if(st_sp)": "Add validation for the key variable",
        "update if(sp)": "Modify the conditional validation for the key variable",
        "+if(sp_i)": "Add validation for the key variable",
        "replace(other variable(integer))": "Substitute the key variable with another variable",
        "+if(sp->integer)": "Add validation for the key variable",
        "update if(sp->integer)": "modify the pointer validation logic for key variable",
        "+if(st.sp)": "Add validation for the key variable",
    }
        self.vul_total=0
        self.fix_total=0
        self.client = OpenAI(
            base_url="",
        api_key=os.getenv("OPENAI_API_KEY", "your api key"),
        http_client=http_client,
        )
    
    def save_messages_to_json(self,filename,messages):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(messages, f, ensure_ascii=False, indent=4)
    
    def run_LLM(self,json_file):
        try:
            with open(json_file, "r") as f:
                datas = json.load(f)
        except Exception as e:
            print(f"Failed to load JSON file: {json_file}. Error: {e}")
            return
        i=0
        for data in datas:
            vul=set()
            if "func" not in data:
                continue
            i=i+1
            print("Entry {}".format(i))
            key_variable=list(data['type_mapping'].keys())
            code=data['func']
            variable_type1=list(data['type_mapping'].values())
            messages = [
                    {"role": "system", "content": "You are a vulnerability detection expert."},
                ]
            combined_vul_direct=set()
            combined_vul_indirect=set()
            for type1 in variable_type1:
                vul1=run(find_vul_direct,type1)
                vul2=run(find_vul_indirect,type1)
                combined_vul_direct.update(vul1)
                combined_vul_indirect.update(vul2)
                vul.update(vul1)
                vul.update(vul2)
            direct_list=sorted(combined_vul_direct)
            indirect_list=sorted(combined_vul_indirect)
            if vul:
                base_prompt = f"""
                Analyze the following code to determine whether it contains potential vulnerabilities. Consider the variable '{key_variable}' in your analysis.

                Code:
                '''
                {code}
                '''
                """

                direct_desc = ", ".join(direct_list)
                indirect_desc = ", ".join(indirect_list)
                vul_types_desc = ", ".join(sorted(vul))
                if not direct_list and indirect_list:
                    reasoning = f"According to the knowledge graph, {key_variable} may indirectly trigger {indirect_desc} vulnerabilities or other vulnerabilities by transforming other variables."
                elif direct_list and not indirect_list:
                    reasoning = f"According to the knowledge graph, {key_variable} may directly trigger {direct_desc} vulnerabilities or other vulnerabilities since it appears in vulnerability-related lines."
                elif direct_list and indirect_list:
                    reasoning = f"According to the knowledge graph, {key_variable} may directly trigger {direct_desc} vulnerabilities (appears in vulnerability-related lines) or indirectly trigger {indirect_desc} vulnerabilities by transforming other variables, or other vulnerabilities."
                
                vul_field = "None" if not vul_types_desc else f"None, {vul_types_desc}, others"
                messages.append({
                    "role": "user",
                    "content": f"""
                {base_prompt}

                Additional context: {reasoning}

                Please provide your security assessment in exactly the following format:
                {{
                    "Vulnerability_Present?": "True or False",
                    "Vulnerability_types": "{vul_field}"
                }}

                Do not provide any explanation or additional details.
                """
                })
                self.chat_with_pirate(messages)
                response1=messages[-1]['content']
                print(messages[-1]['content'])
                pattern = r'\{[^{}]*\}'
                matches = re.findall(pattern, response1)
                if matches:
                    try:
                        R1 = json.loads(matches[0])
                        data['predict']=(json.loads(matches[0])['Vulnerability_Present?'])
                        print("Matched vulnerability characteristics, initial judgment: {}".format(data['predict']))
                        print(R1)
                        FIX=[]
                        print(R1['Vulnerability_types'])
                        if R1['Vulnerability_types'] !="None" and "True" in R1['Vulnerability_Present?']:
                            for v in R1['Vulnerability_types'].strip().split(","):
                                v=v.strip()
                                if v in combined_vul_indirect and v in combined_vul_direct:
                                    fix1=run(find_fix_direct,variable_type1,v)
                                    fix1=[self.fix_dict[i] for i in fix1]
                                    iv=run(find_iv,variable_type1,v)
                                    fix2=[run(find_fix_indirect,i, v) for i in iv]
                                    flat_fix2 = [item for sublist in fix2 for item in sublist]
                                    fix2=[self.fix_dict[i] for i in flat_fix2]
                                    fix2=set(fix2)
                                    FIX.append(fix1)
                                    FIX.append(fix2)
                                elif (v in combined_vul_direct) and v not in combined_vul_indirect :
                                    fix1=run(find_fix_direct,variable_type1,v)
                                    fix1=[self.fix_dict[i] for i in fix1]
                                    FIX.append(fix1)
                                elif v in combined_vul_indirect and v not in combined_vul_direct:
                                    iv=run(find_iv,variable_type1,v)
                                    fix1=[run(find_fix_indirect,i, v) for i in iv]
                                    flat_fix1 = [item for sublist in fix1 for item in sublist]
                                    fix1=[self.fix_dict[i] for i in flat_fix1]
                                    fix1=set(fix1)
                                    FIX.append(fix1)
                            if FIX:
                                user_input=f"In your previous response, the variable {key_variable} will trigger {R1['Vulnerability_types']}. But the code might include mitigations such as {', '.join(str(fix) for fix in FIX)} or other security measures to address it. Re-evaluate and reply only with True (if a vulnerability exists) or False, without any further explanation."
                            else:
                                self.fix_total+=1
                                user_input=f"In your previous response, the variable {key_variable} will trigger {R1['Vulnerability_types']}. But the code might include other security measures to address it. Re-evaluate and reply only with True (if a vulnerability exists) or False, without any further explanation."
                            messages.append({"role": "user", "content": user_input})
                            self.chat_with_pirate(messages)
                            response2=messages[-1]['content']
                            data['predict']=response2
                            print("Found direct and indirect fixes, second judgment: {}".format(data['predict']))                              

                    except json.JSONDecodeError as e:
                        print(f"JSON parsing error: {e}")
                        print(f"Original data: {response1}")
                        data['predict']=response1
                        
            else:
                self.vul_total+=1
                print("===================")
                print(vul)
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
                print(messages[-1]['content'])
                data['predict']=(messages[-1]['content'])
        self.save_messages_to_json('KGVD/result/CWE476/claude/function/KGVD2_primevul.json',datas)
        print(self.vul_total)   
        print(self.fix_total)
        
    def chat_with_pirate(self,messages):
        response =self.client.chat.completions.create(
            model="claude-3-5-sonnet-20240620",
            messages=messages
        )
        response_content = response.choices[0].message.content
        messages.append({"role": "assistant", "content": response_content})


run1 =Run()
run1.run_LLM("primevul-476.json")