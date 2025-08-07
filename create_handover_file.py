# create_handover_file.py
# -*- coding: utf-8 -*-

import os
import textwrap

# =================================================================================
# 1. 更新后的文件清单 (根据最新的文件结构)
# =================================================================================
# 这个列表现在包含了项目的所有核心文件，并按照模块进行了分组
FILES_TO_INCLUDE = [
    # --- 根目录核心文件 ---
    'run.py',
    'config.py',

    # --- 测试脚本 ---
    'api_test_script.py',
    'workflow_test_script.py',
    'e2e_test_script.py',

    # --- App 核心模块 ---
    'app/__init__.py',
    'app/models.py',
    'app/analyzer_test_script.py',

    # --- API 路由模块 ---
    'app/api/__init__.py',
    'app/api/auth_routes.py',
    'app/api/device_routes.py',
    'app/api/log_stream_routes.py', # <-- 新增
    'app/api/project_routes.py',
    'app/api/user_routes.py',
    'app/api/workflow_routes.py',

    # --- 服务层模块 ---
    'app/services/__init__.py',
    'app/services/auth_service.py',
    'app/services/device_service.py',
    'app/services/project_analyzer_service.py',
    'app/services/user_service.py',
    'app/services/syntax_analyzer_service.py',
    'app/services/workflow_service.py',

    # --- LangGraph 定义 ---
    'app/langgraph_def/__init__.py',
    'app/langgraph_def/agent_state.py',
    'app/langgraph_def/graph_builder.py',

    # --- 前端模板 ---
    'app/templates/index.html',
]

# =================================================================================
# 2. 交接备忘录 (内容保持不变)
# =================================================================================
HANDOVER_MEMO = textwrap.dedent("""
""")


# =================================================================================
# 3. 功能: 生成项目文件结构树 (代码保持不变)
# =================================================================================
def generate_file_tree(start_path='.'):
    """生成项目目录结构的可视化字符串"""
    tree_lines = [f"{os.path.basename(os.path.abspath(start_path))}/"]
    # 忽略不必要展示的目录和文件
    ignore_dirs = {'__pycache__', '.git', '.idea', 'venv', 'workspace'}
    ignore_files = {'.DS_Store', 'handover.txt', 'dev-db.sqlite'}

    for root, dirs, files in os.walk(start_path, topdown=True):
        # 过滤掉需要忽略的目录
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        level = root.replace(start_path, '').count(os.sep)
        indent = ' ' * 4 * level

        # 打印子目录
        sub_indent = ' ' * 4 * (level + 1)
        for d in sorted(dirs):
            tree_lines.append(f'{sub_indent}├── {d}/')

        # 打印文件
        for f in sorted(files):
            if f not in ignore_files:
                tree_lines.append(f'{sub_indent}└── {f}')

    return "\\n".join(tree_lines)


def create_handover_file():
    """
    主函数：创建交接单文件。
    """
    output_filename = "handover.txt"
    try:
        with open(output_filename, 'w', encoding='utf-8') as f_out:
            # 写入备忘录
            f_out.write(HANDOVER_MEMO)
            f_out.write("\\n\\n")

            # 写入项目文件结构
            f_out.write("--- 项目文件结构 ---\\n")
            f_out.write("```\\n")
            # 我们从'app'目录开始生成树，以获得更清晰的视图
            f_out.write(generate_file_tree())
            f_out.write("\\n```\\n")

            # 写入所有文件内容
            for filepath in FILES_TO_INCLUDE:
                # 兼容Windows和Linux的路径分隔符
                normalized_path = os.path.join(*filepath.split('/'))
                separator = f"\\n--- FILE: {filepath} ---\\n"
                print(f"正在打包文件: {filepath}")
                f_out.write(separator)

                try:
                    with open(normalized_path, 'r', encoding='utf-8') as f_in:
                        f_out.write(f_in.read())
                except FileNotFoundError:
                    f_out.write(f"# <<< 文件未找到: {filepath} >>>")
                    print(f"  警告: 文件 {filepath} 未找到，已在交接单中标记。")

        print(f"\\n成功！项目交接单 '{output_filename}' 已生成在您的项目根目录。")
        print("新的交接单现在包含了更新后的文件列表和项目结构树。")

    except Exception as e:
        print(f"\\n生成交接单时发生错误: {e}")


if __name__ == '__main__':
    create_handover_file()
