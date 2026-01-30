import json
from openai import OpenAI, OpenAIError
import httpx
import os

client = OpenAI(
    base_url="",
    api_key=os.getenv("OPENAI_API_KEY", ""),
)

def run_LLM(json_file, output_file):
    with open(json_file, "r") as f:
        datas = json.load(f)
    
    i = 0
    results = []
    
    for data in datas:
        i = i + 1
        print("Entry {}".format(i))
        
        source_code = data['function_code']
        critical_vars = data['critical_vars']
        
        if not isinstance(critical_vars, list):
            print(f"第{i}条: critical_vars格式错误，期望列表，实际得到{type(critical_vars)}，跳过")
            data['variable_definitions'] = {}
            results.append(data)
            continue
        
        variable_names = [var.strip() for var in critical_vars]
        
        print(f"Processing variables: {variable_names}")

        messages = [
            {
                "role": "system", 
                "content": "You are a code analysis expert. Extract variable definitions exactly as they appear in the code, without any additional explanations."
            },
            {
                "role": "user", 
                "content": """
                    Task: Extract variable definitions from code

                    ## Instruction
                    Find and extract the complete definition statements of the specified variables from the provided code. Output each definition on a separate line.

                    ## Rules
                    - For each variable, output the complete definition statement exactly as it appears in the code
                    - If a variable definition is not found, output "Definition not found" for that variable
                    - Output format: one line per variable in the order they are requested
                    - No explanations, no additional text, no code blocks
                    - Handle all types of variables: pointers, arrays, structs, basic types, etc.

                    ## Examples

                    Example 1: Pointer variables
                    Input:
                    Variables: *raw, *data
                    Code:
                    #include <stdio.h>
                    #include <stdlib.h>
                    int main() {
                        char *raw = malloc(100);
                        unsigned char *data = raw + 10;
                        return 0;
                    }
                    Output:
                    char *raw = malloc(100);
                    unsigned char *data = raw + 10;

                    Example 2: Mixed variables
                    Input:
                    Variables: size, buffer, count
                    Code:
                    void process() {
                        int size = 100;
                        char buffer[50];
                        static int count = 0;
                    }
                    Output:
                    int size = 100;
                    char buffer[50];
                    static int count = 0;

                    Example 3: Array and struct variables
                    Input:
                    Variables: arr, student
                    Code:
                    struct Student {
                        char name[50];
                        int age;
                    };
                    int arr[10];
                    struct Student student;
                    Output:
                    int arr[10];
                    struct Student student;

                    Example 4: Not found cases
                    Input:
                    Variables: *p, temp, index
                    Code:
                    for (int i = 0; i < 10; i++) {
                        *p = i;
                        temp = i * 2;
                    }
                    Output:
                    Definition not found
                    Definition not found
                    Definition not found

                    Now process the following request:
                    """
                                },
                                {
                                    "role": "user",
                                    "content": f"""
                    Variables: {', '.join(variable_names)}
                    Code:
                    {source_code}

                    Definitions:
                    """
            }
        ]

        try:
            response = client.chat.completions.create(
                model="gpt-5",
                messages=messages,
            )
            
            response_content = response.choices[0].message.content.strip()
            print(f"LLM response: {response_content}")
            
            definitions = [line.strip() for line in response_content.split('\n') if line.strip()]
            
            while len(definitions) < len(variable_names):
                definitions.append("Definition not found")
            
            definitions = definitions[:len(variable_names)]
            
            var_definitions = {}
            for var, definition in zip(variable_names, definitions):
                var_definitions[var] = definition
            
            data['variable_definitions'] = var_definitions
            results.append(data)
            
        except Exception as e:
            print(f"Entry {i} processing failed: {e}")
            data['variable_definitions'] = {var: "Error" for var in variable_names}
            results.append(data)
    
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nProcessing complete! Processed {len(datas)} entries")
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    input_file = "/workdir/test/RESULT_filter_CWE189.json"
    output_file = "/workdir/test/RESULT_with_definitions_CWE189.json"
    run_LLM(input_file, output_file)