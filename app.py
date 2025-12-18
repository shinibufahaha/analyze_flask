from flask import Flask, render_template, jsonify
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter

app = Flask(__name__)

# 模拟的路径数据：Source -> Filter -> Sink
# highlighted_lines 是你希望高亮显示的行号列表（从1开始）
PATH_DATA = [
    {
        "id": "func_a",
        "label": "get_user_input()",
        "highlighted_lines": [2],
        "code": """def get_user_input():
    user_data = request.args.get('input') # Source
    return user_data"""
    },
    {
        "id": "func_b",
        "label": "sanitize_data(data)",
        "highlighted_lines": [],
        "code": """def sanitize_data(data):
    # 这里的过滤逻辑可能不完整
    if "script" in data:
        return ""
    return data"""
    },
    {
        "id": "func_c",
        "label": "exec_command(cmd)",
        "highlighted_lines": [2],
        "code": """def exec_command(cmd):
    import os
    os.system(cmd) # Sink: 危险操作
    return True"""
    }
]

# 定义边的关系
EDGES = [
    {"source": "func_a", "target": "func_b"},
    {"source": "func_b", "target": "func_c"}
]

def get_highlighted_code(code, lines_to_highlight):
    """
    使用 Pygments 将代码转换为 HTML，并高亮指定行
    """
    formatter = HtmlFormatter(
        style='monokai', 
        linenos=True, 
        hl_lines=lines_to_highlight, 
        cssclass="code-highlight"
    )
    return highlight(code, PythonLexer(), formatter)

@app.route('/')
def index():
    # 预处理数据：将原始代码转换为高亮的 HTML
    nodes = []
    for node in PATH_DATA:
        html_content = get_highlighted_code(node['code'], node['highlighted_lines'])
        nodes.append({
            "data": {
                "id": node['id'],
                "label": node['label'],
                "code_html": html_content  # 将渲染好的HTML传给前端
            }
        })
    
    edges = [{"data": edge} for edge in EDGES]
    
    # 获取 Pygments 的 CSS 样式，以便注入到 HTML 头部
    css_style = HtmlFormatter(style='monokai').get_style_defs('.code-highlight')
    
    return render_template('index.html', nodes=nodes, edges=edges, css_style=css_style)

if __name__ == '__main__':
    app.run(debug=True)