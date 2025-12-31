import sys
import json
import os
import google.generativeai as genai

# 1. 配置
genai.configure(api_key="AIzaSyAt2kx2giI5hp2cgCTEql5yyaMqzcCERAc")




SYSTEM_PROMPT = {"a": """
你是一个专业的安卓代码审查人员
你的任务是：
1. 接收用户输入的函数调用链（包括函数签名和代码）
2. 判断调用链中是否存在launchAnywhere漏洞
3. 如果调用链中存在getParcelable或getParcelableExtra,且返回类型是intent,那么你需要特别注意这个intent是否作为startActivity类函数的参数
4. 以 JSON 格式返回结果, JSON格式如下
{
"存在漏洞": "yes/no"
"结论依据": ""
}
""",

"r": """
你是一个专业的安卓代码审查人员
你的任务是：
1. 阅读理解用户输入的Receiver注册代码
2. 着重关注注册的Receiver是否暴露, 具体来说, 你需要关注Receiver的Action是否是普通应用可发送广播的Action; Receiver是否被权限保护,如果权限是你已知的系统权限, 则认为Receiver不暴露; 最后就是exported的Flag是否显示设置为2,只考虑高版本的Android版本, 如果不显示设置，则默认不暴露
3. 第2条里的三个条件必须都满足, 注册的Receiver才算作暴露
4. 以 JSON 格式返回结果, JSON格式如下
{
"是否暴露": "yes/no"
"结论依据": ""
}
"""
}



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


def analyze_activity(input_dir, output_file):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith("call_chain.json"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r") as f:
                    try:
                        json_data = json.load(f)
                    except:
                        continue

                    for component, call_chains in json_data.items():
                        if component not in all_results:
                            all_results[component] = []
                        
                        # 对每个调用链进行分析
                        for chain in call_chains:
                            print(f"分析组件: {component}...")
                            result = analyze_content(chain)
                            
                            # 更新内存中的结果
                            all_results[component].append(result)

                            # --- 关键：实时写入文件 ---
                            with open(output_file, "w") as f_out:
                                json.dump(all_results, f_out, indent=4, ensure_ascii=False)
                                f_out.flush() # 强制写入磁盘
                            
                            print(f"Done. 结果已更新。")


def analyze_receiver(input_dir, output_file):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith("register_receiver_refs.json"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r") as f:
                    try:
                        json_data = json.load(f)
                    except:
                        continue
                    for r in json_data:
                        caller_method = r["caller_method"]
                        if caller_method not in all_results:
                            all_results[caller_method] = []
                        code = r["code"]
                        reuslt = analyze_content(code)
                        all_results[caller_method].append(reuslt)
                        with open(output_file, "w") as f_out:
                            json.dump(all_results, f_out, indent=4, ensure_ascii=False)
                            f_out.flush() # 强制写入磁盘
                            
                            print(f"Done. 结果已更新。")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python script.py <mode> <input_dir> <output_file>")
        sys.exit(1)

    mode = sys.argv[1]
    input_dir = sys.argv[2]
    output_file = sys.argv[3]

    # 3. 初始化模型时直接注入系统提示词
    model = genai.GenerativeModel(
        model_name='gemini-3-flash-preview', # 建议使用稳定版名称
        system_instruction=SYSTEM_PROMPT[mode]
    )
    
    # 初始化结果字典
    all_results = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                all_results = json.load(f)
        except:
            all_results = {}

    print(f"正在分析中，结果将实时保存至: {output_file}")
    if mode == "a":
        analyze_activity(input_dir, output_file)
    elif mode == "r":
        analyze_receiver(input_dir, output_file)