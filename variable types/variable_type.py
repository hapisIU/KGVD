import json
from openai import OpenAI, OpenAIError
import httpx
import os
import time

client = OpenAI(
    base_url="",
    api_key=os.getenv("OPENAI_API_KEY", ""),
)

def run_LLM(json_file, output_file):
    try:
        with open(json_file, "r", encoding='utf-8') as f:
            datas = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"File loading failed: {e}")
        return
    
    i = 0
    results = []
    total_count = len(datas)
    
    for data in datas:
        i = i + 1
        print(f"Entry {i}/{total_count}")
        
        definition_dict = data.get('variable_definitions', {})
        critical_vars = data.get('critical_vars', [])
        function_code = data.get('function_code', '')
        
        if not isinstance(critical_vars, list) or not isinstance(definition_dict, dict):
            print(f"  Data format error, skipping")
            data['variable_types'] = {}
            results.append(data)
            continue
        
        variable_names = [var.strip() for var in critical_vars]
        print(f"  Processing variables: {variable_names}")

        var_types = {}
        for var_name in variable_names:
            definition = definition_dict.get(var_name, "Definition not found")
            print(f"  Analyzing variable '{var_name}': '{definition}'")
            
            type_result = analyze_single_variable(var_name, definition, function_code)
            var_types[var_name] = type_result
            print(f"    Type: {type_result}")
            
            time.sleep(0.5)
        
        data['variable_types'] = var_types
        results.append(data)
    
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nProcessing complete! Processed {len(datas)} entries")
    print(f"Results saved to: {output_file}")

def analyze_single_variable(var_name, definition, function_code):
    """Analyze the type of a single variable, providing definition and code context"""
    
    code_preview = function_code
    
    prompt_content = """
    You are a professional code analysis expert. Accurately determine variable types based on variable definition statements and code context.

    ## Type Classification Rules:

    ### Primary Types:
    - integer (includes: int, int32_t, int64_t, short, long, size_t, uint8, uint16, uint32, uint64, etc.)
    - char (includes: char, unsigned char, uchar, etc.)
    - float (includes: float, double, long double, etc.)

    ### Secondary Types (must be specified):

    **Struct Types:**
    - struct (includes all user-defined types and structs)

    **Array Types:**
    - char array
    - integer array
    - float array
    - struct array
    - char pointer array
    - integer pointer array
    - float pointer array
    - struct pointer array

    **Pointer Types:**
    - char pointer
    - struct pointer
    - integer pointer
    - float pointer

    ## Judgment Rules:
    1. Judge types based on the variable definition statement AND code context
    2. If definition is "Definition not found", infer type from code usage patterns
    3. All struct types and user-defined types are uniformly classified as "struct"
    4. If only struct/user-type declaration without member information is provided, also classify as struct
    5. For pointer, struct, and array types, must provide corresponding secondary types
    6. Pointer arrays must clearly specify the pointed type
    7. uchar, unsigned char are classified as char type
    8. int32_t, int64_t, size_t, short, long, uint8, uint16, uint32, uint64, etc. are all classified as integer type
    9. float, double, long double are classified as float type
    10. User-defined types (non-standard types) are classified as struct
    11. Use code context to infer type when definition is not available
    12. If the type cannot be determined, output "unknown"

    ## Examples:

    Definition: `int *p;`
    Type: integer pointer

    Definition: `float value;`
    Type: float

    Definition: `double *dptr;`
    Type: float pointer

    Definition: `float arr[10];`
    Type: float array

    Definition: `uint8 *cp0;`
    Type: integer pointer

    Definition: `Definition not found`
    Code shows: `cp0 = buffer;` (where buffer is char*)
    Type: char pointer

    Definition: `Definition not found`
    Code shows: `count = 10;`
    Type: integer

    Definition: `Definition not found`
    Code shows: `price = 10.5;`
    Type: float

    Definition: `Definition not found`
    Code shows: `data[i] = value;` (array indexing)
    Type: integer array

    Definition: `uint32_t *ptr;`
    Type: integer pointer

    Definition: `char buffer[100];`
    Type: char array

    Definition: `unsigned char data[256];`
    Type: char array

    Definition: `int32_t count;`
    Type: integer

    Definition: `uint8 byte;`
    Type: integer

    Definition: `struct Node {{ int data; char name[20]; }} node;`
    Type: struct

    Definition: `struct Node *node;`
    Type: struct pointer

    Definition: `struct Student students[50];`
    Type: struct array

    Definition: `int arr[10][20];`
    Type: integer array

    Definition: `char **argv;`
    Type: char pointer

    Definition: `int num;`
    Type: integer

    Definition: `uchar byte;`
    Type: char

    Definition: `size_t length;`
    Type: integer

    Definition: `struct Data {{ char *ptr; int count; }} data;`
    Type: struct

    Definition: `MyCustomType obj;`
    Type: struct

    Definition: `CustomStruct *ptr;`
    Type: struct pointer

    Definition: `char *names[] = {{"Alice", "Bob"}};`
    Type: char pointer array

    Definition: `int *arr[10];`
    Type: integer pointer array

    Definition: `struct Node *nodes[50];`
    Type: struct pointer array

    Definition: `unsigned char *pixels;`
    Type: char pointer

    Definition: `int32_t *values;`
    Type: integer pointer

    Definition: `uint8 *data_ptr;`
    Type: integer pointer

    Definition: `unknown_type var;`
    Type: unknown

    Definition: `custom_type data;`
    Type: struct

    Definition: `void *ptr;`
    Type: unknown

    ## Special Case Handling:
    - All struct types and user-defined types uniformly use "struct"
    - Pointer arrays must clearly specify the pointed type
    - Multi-dimensional arrays are uniformly identified as array types
    - uchar/unsigned char are classified as char
    - Various integer type aliases (int32_t, uint8, uint16, uint32, uint64, size_t, etc.) are classified as integer
    - float, double, long double are classified as float
    - User-defined types (non-standard types) are classified as struct
    - When definition is "Definition not found", infer type from code usage patterns
    - Look for array indexing, pointer dereferencing, function calls to infer type
    - If type cannot be determined from the definition and context, output "unknown"

    ## Output Requirements:
    - Output only the type name, no explanations
    - Must include complete secondary types (if applicable)
    - Judge based on definition statement and code context
    - Prohibit using vague type names
    - Use "unknown" when type cannot be determined

    Now please analyze the following variable definition and output the corresponding type:

    Variable: {var_name}
    Definition: `{definition}`

    Function Code Context:
    {code_preview}

    Type:
    """.format(var_name=var_name, definition=definition, code_preview=code_preview)
        
    messages = [
        {
            "role": "system", 
            "content": "You are a professional code analysis expert. Accurately determine variable types based on variable definition statements and code context."
        },
        {
            "role": "user", 
            "content": prompt_content
        }
    ]
    
    try:
        response = client.chat.completions.create(
            model="gpt-5",
            messages=messages
        )
        
        response_content = response.choices[0].message.content.strip()
        return response_content
        
    except Exception as e:
        print(f"    API call failed: {e}")
        return "unknown"

if __name__ == "__main__":
    input_file = "/workdir/test/RESULT_with_definitions.json"
    output_file = "/workdir/test/RESULT_with_definitions_type.json"
    run_LLM(input_file, output_file)