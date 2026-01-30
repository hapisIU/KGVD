#!/usr/bin/env python3
"""
为 CWE189_with_labels.json 添加 function_code 字段的脚本

根据每个条目的 filename 和 label，从对应的 .c 文件中提取函数代码
"""

import json
import os
import re
from pathlib import Path


def extract_function_code(c_file_path, function_name):
    if not os.path.exists(c_file_path):
        return "File not found"
    
    if not function_name or function_name.strip() == "" or function_name == "None_func":
        return "Function name not provided"
    
    try:
        with open(c_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        clean_function_name = function_name.lstrip('*').strip()
        
        if not clean_function_name:
            return "Invalid function name"
        
        escaped_name = re.escape(clean_function_name)
        
        patterns = [
            rf'^\s*[\w\s]+\s*\*\s*{escaped_name}\s*\([^{{]*?\)\s*\{{',
            rf'^\s*[\w\s\*]+\s+{escaped_name}\s*\([^{{]*?\)\s*\{{',
            rf'^\s*(?:static\s+)?(?:inline\s+)?[\w\s\*]+\s+{escaped_name}\s*\([^{{]*?\)\s*\{{',
            rf'^\s*(?:static\s+)?(?:inline\s+)?[\w\s]+\s*\*\s*{escaped_name}\s*\([^{{]*?\)\s*\{{',
            rf'^\s*[\w_]+\([^)]*{escaped_name}[^)]*\)\s*\{{',
        ]
        
        for pattern in patterns:
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            
            if matches:
                match = matches[0]
                start_pos = match.start()
                
                brace_start = content.index('{', start_pos)
                
                brace_count = 0
                pos = brace_start
                in_string = False
                in_char = False
                escape_next = False
                
                while pos < len(content):
                    char = content[pos]
                    
                    if escape_next:
                        escape_next = False
                        pos += 1
                        continue
                    
                    if char == '\\':
                        escape_next = True
                        pos += 1
                        continue
                    
                    if char == '"' and not in_char:
                        in_string = not in_string
                    elif char == "'" and not in_string:
                        in_char = not in_char
                    
                    if not in_string and not in_char:
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                function_code = content[start_pos:pos+1]
                                return function_code
                    
                    pos += 1
                
                return content[start_pos:start_pos+2000] + "\n... (function end not found)"
        
        return "Function not found"
    
    except Exception as e:
        return f"Error extracting function: {str(e)}"


def process_json_file(input_file, data_dir, output_file):
    """
    Process JSON file and add function_code field
    
    Args:
        input_file: Input JSON file path
        data_dir: Root directory where .c files are located
        output_file: Output JSON file path
    """
    print(f"Reading file: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Total {len(data)} records")
    
    success_count = 0
    not_found_count = 0
    error_count = 0
    
    for idx, entry in enumerate(data):
        if idx % 50 == 0:
            print(f"Processing progress: {idx}/{len(data)}")
        
        filename = entry.get('filename', '')
        function_name = entry.get('function', '')
        label = entry.get('label', 'unknown')
        
        if not filename:
            entry['function_code'] = "No filename provided"
            error_count += 1
            continue
        
        parts = filename.split('/')
        if len(parts) < 3:
            entry['function_code'] = "Invalid filename format"
            error_count += 1
            continue
        
        repo_name = parts[0]
        cve_id = parts[1]
        diff_filename = parts[2]
        
        if diff_filename.endswith('.diff'):
            base_filename = diff_filename[:-5]
        else:
            entry['function_code'] = "Invalid diff filename"
            error_count += 1
            continue
        
        if label == 'True':
            c_filename = f"{base_filename}_NEW.c"
        elif label == 'False':
            c_filename = f"{base_filename}_OLD.c"
        else:
            entry['function_code'] = "Unknown label"
            error_count += 1
            continue
        
        c_file_path = os.path.join(data_dir, repo_name, cve_id, c_filename)
        
        function_code = extract_function_code(c_file_path, function_name)
        entry['function_code'] = function_code
        
        if "not found" in function_code.lower() or "error" in function_code.lower():
            if "File not found" in function_code:
                error_count += 1
            else:
                not_found_count += 1
        else:
            success_count += 1
    
    print(f"\nSaving to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    
    print(f"\nProcessing complete!")
    print(f"=" * 60)
    print(f"Successfully extracted function code: {success_count}")
    print(f"Function not found: {not_found_count}")
    print(f"File errors: {error_count}")
    print(f"Total: {len(data)}")
    print(f"=" * 60)
    print(f"\nNew file saved to: {output_file}")


def main():
    input_file = '/variable types/CWE189_with_labels.json'
    data_dir = '/variable types/0_data/CWE-189'
    output_file = '/variable types/CWE189_with_function_code.json'
    
    process_json_file(input_file, data_dir, output_file)


if __name__ == '__main__':
    main()

