import subprocess
import tempfile
import re
import os
import py_compile
import json
from typing import Optional

ERROR_PATTERN = re.compile(r'^\[.+?\]:(\d+):(\d+):\s+\((error|warning|style)\)\s+\[.+?\]\s+(.+)$', re.MULTILINE)


def _to_pos_int(value, default=1):
    """
    把任何行号 / 列号转换为 >=1 的 int。
    非法值统一返回 default。
    """
    try:
        iv = int(value)
        return iv if iv > 0 else default
    except (TypeError, ValueError):
        return default

def analyze_cpp_code(code: str, workspace_path: Optional[str] = None):
    """
    【V3 重构版】C++代码分析的统一入口。
    自动根据是否存在有效工作区路径来选择最佳分析引擎。
    """
    # 决策：如果提供了有效的工作区路径，则使用功能更强大的项目分析器
    if workspace_path and os.path.isdir(workspace_path):
        print(f"\n--- [ANALYZE ENGINE] Using PROJECT mode (PlatformIO) for workspace: {workspace_path} ---")
        return _analyze_cpp_project_with_pio(code, workspace_path)

    # 否则，回退到单文件分析器
    print("\n--- [ANALYZE ENGINE] Using SINGLE-FILE mode (cppcheck) ---")
    return _analyze_cpp_file_with_cppcheck(code)


def _analyze_cpp_project_with_pio(code: str, workspace_path: str):
    """项目分析模式：使用 PlatformIO check 工具进行静态分析。"""
    errors = []
    # 假设需要更新的文件是 app_main.ino，这可以根据需要进行扩展
    main_ino_path = os.path.join(workspace_path, 'src', 'app_main.ino')
    original_content = ""
    if not os.path.exists(main_ino_path):
        # 如果项目结构不完整，无法进行分析
        return {"success": True, "errors": [
            {'line': 1, 'column': 1, 'message': '项目文件 (src/app_main.ino) 不存在，无法执行项目级分析。'}]}

    try:
        with open(main_ino_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        with open(main_ino_path, 'w', encoding='utf-8') as f:
            f.write(code)

        command = ['platformio', 'check', '--fail-on-error', '--json-output']
        print(f"--- [DEBUG] Executing command in '{workspace_path}': {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, cwd=workspace_path, timeout=60,
                                encoding='utf-8')

        print(f"--- [DEBUG] pio check return code: {result.returncode}")
        print(f"--- [DEBUG] pio check stdout:\n{result.stdout.strip()}")
        print(f"--- [DEBUG] pio check stderr:\n{result.stderr.strip()}")

        try:
            # PlatformIO check 的 JSON 输出是每行一个对象
            for line in result.stdout.strip().splitlines():
                if line.startswith('{') and line.endswith('}'):
                    issue = json.loads(line)
                    errors.append({
                        'line': _to_pos_int(issue.get('line', 1)),
                        'column': _to_pos_int(issue.get('column', 1)),
                        'message': f"[{issue.get('tool', 'pio')}] {issue.get('message', 'Unknown error')}",
                        'severity': issue.get('severity', 'error').lower()
                    })
        except json.JSONDecodeError:
            error_output = result.stderr or result.stdout
            if error_output:
                errors.append({'line': 1, 'column': 1, 'severity': 'error',
                               'message': f'PlatformIO check failed: {error_output}'})

    except Exception as e:
        errors.append({'line': 1, 'column': 1, 'severity': 'error',
                       'message': f'An unexpected error occurred during analysis: {e}'})
    finally:
        # 无论成功失败，都恢复原始文件内容
        if original_content:
            with open(main_ino_path, 'w', encoding='utf-8') as f:
                f.write(original_content)

    return {"success": True, "errors": errors}


def _analyze_cpp_file_with_cppcheck(code: str):
    """基础分析模式：使用 cppcheck 对单个C++文件进行分析。"""
    errors = []
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.cpp', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name

        command = [
            'cppcheck', '--enable=all', '--suppress=missingIncludeSystem',
            f'--template=[{{file}}]:{{line}}:{{column}}: ({{severity}}) [{{id}}] {{message}}',
            temp_file_path
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore')
        combined_output = result.stdout + result.stderr

        if combined_output:
            for match in ERROR_PATTERN.finditer(combined_output):
                errors.append({
                    'line': _to_pos_int(match.group(1)),
                    'column': _to_pos_int(match.group(2)),
                    'severity': match.group(3).lower(),
                    'message': match.group(4).strip()
                })

    except FileNotFoundError:
        errors.append(
            {'line': 1, 'column': 1, 'severity': 'error', 'message': '代码检查器 (cppcheck) 未在服务器上找到。'})
    except Exception as e:
        errors.append({'line': 1, 'column': 1, 'severity': 'error',
                       'message': f'An unexpected error during cppcheck analysis: {e}'})
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    return {"success": True, "errors": errors}


def analyze_python_syntax(code: str):
    """(保持不变) 对Python代码进行静态语法分析。"""
    errors = []
    try:
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.py', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name
        py_compile.compile(temp_file_path, doraise=True)
    except py_compile.PyCompileError as e:
        errors.append({
            'line': _to_pos_int(getattr(e, 'lineno', 1)),
            'column': _to_pos_int(getattr(e, 'offset', 1)),
            'severity': 'error',
            'message': e.msg
        })
    except Exception as e:
        errors.append({'line': 1, 'column': 1, 'severity': 'error', 'message': f'Python analysis failed: {e}'})
    finally:
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
    return {"success": True, "errors": errors}