import sys
import json
import os
import google.generativeai as genai

# 1. 配置
genai.configure(api_key="AIzaSyAt2kx2giI5hp2cgCTEql5yyaMqzcCERAc")

# 2. 定义系统提示词 (System Instruction)
# 在这里告诉模型它的角色、分析逻辑和输出格式
SYSTEM_PROMPT = """
你是一个专业的安卓代码审查人员
你的任务是：
1. 接收用户输入的provider反编译代码
2. 判断provider的敏感接口是否存在鉴权, 如果没有鉴权，则进一步判断接口是否能泄漏敏感信息或者执行敏感操作
3. 如果provider的接口存在鉴权, 则判断鉴权逻辑是否可绕过, 比如调用了getCallingPid()或者从intent中的数据获取调用者的包名,或者鉴权逻辑的与或符号使用不当
4. 大部分情况下, 请忽略getType接口,因为这个接口一般不敏感
5. 
5. 以 JSON 格式返回结果, JSON格式如下
{
"存在漏洞": "yes/no"
"结论依据": ""
}
"""

# 3. 初始化模型时直接注入系统提示词
model = genai.GenerativeModel(
    model_name='gemini-3-flash-preview', # 建议使用稳定版名称
    system_instruction=SYSTEM_PROMPT
)

def analyze_content(call_chain_data):
    try:
        # 将输入转为字符串发送
        user_content = json.dumps(call_chain_data, ensure_ascii=False)
        response = model.generate_content(
            user_content,
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        # 解析返回的 JSON 字符串为对象
        return json.loads(response.text)
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <input_dir> <output_file>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    
    # 初始化结果字典
    all_results = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                all_results = json.load(f)
        except:
            all_results = {}

    print(f"正在分析中，结果将实时保存至: {output_file}")

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith("decompiled_provider_code.json"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r") as f:
                    try:
                        json_data = json.load(f)
                    except:
                        continue
                    
                    for provider, decompiled_code in json_data.items():
                        print(provider)
                        result = analyze_content(decompiled_code)
                        all_results[provider] = result
                            # --- 关键：实时写入文件 ---
                        with open(output_file, "w") as f_out:
                            json.dump(all_results, f_out, indent=4, ensure_ascii=False)
                            f_out.flush() # 强制写入磁盘
                        
                        print(f"Done. 结果已更新。")
                            