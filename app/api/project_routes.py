# app/api/project_routes.py
# -*- coding: utf-8 -*-

import shutil
import tempfile
import zipfile
import uuid
import subprocess
import os
from pathlib import Path
from flask import Blueprint, request, jsonify, g
from app.services import project_analyzer_service, workflow_service, syntax_analyzer_service
from .device_routes import token_required
from app.models import Project
import json
from app import db


def extract_key_errors(output):
    """从完整输出中提取关键错误信息"""
    lines = output.split('\n')
    key_errors = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 提取关键错误信息
        if any(keyword in line.lower() for keyword in [
            'fatal error', 'error:', 'failed', 'timeout', 'could not',
            'wrong --chip', 'not found', 'permission denied', 'access denied',
            'error 2', '*** [upload] error'
        ]):
            key_errors.append(line)

        # 提取串口信息
        if 'serial port' in line.lower():
            key_errors.append(line)

        # 提取芯片类型错误
        if 'this chip is' in line.lower() and 'not' in line.lower():
            key_errors.append(line)

        # 提取TimeoutError
        if 'timeouterror:' in line.lower():
            key_errors.append(line)

    return key_errors


def extract_chip_info(output):
    """从错误输出中提取芯片信息"""
    import re

    # 查找 "This chip is XXX not YYY" 模式
    chip_pattern = r"this chip is (\w+(?:-\w+)*) not (\w+(?:-\w+)*)"
    match = re.search(chip_pattern, output.lower())

    if match:
        actual_chip = match.group(1).upper()
        expected_chip = match.group(2).upper()
        return actual_chip, expected_chip

    return None, None


def get_board_suggestion(chip_type):
    """根据芯片类型返回推荐的board配置"""
    chip_to_board = {
        'ESP32': 'esp32dev',
        'ESP32-S2': 'esp32-s2-saola-1',
        'ESP32-S3': 'esp32-s3-devkitc-1',
        'ESP32-C3': 'esp32-c3-devkitm-1',
        'ESP32-C6': 'esp32-c6-devkitc-1',
        'ESP32-H2': 'esp32-h2-devkitm-1',
        'ESP8266': 'nodemcuv2'
    }
    return chip_to_board.get(chip_type, f'{chip_type.lower().replace("-", "")}dev')


def extract_board_from_error(output):
    """从错误输出中提取当前配置的board信息"""
    import re

    # 查找board配置信息
    board_patterns = [
        r'board based on the declared.*?`([^`]+)`',
        r'for the `([^`]+)` board',
        r'board.*?`([^`]+)`'
    ]

    for pattern in board_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def analyze_flash_error(return_code, output):
    """分析烧录错误并提供解决建议"""
    suggestions = []
    output_lower = output.lower()

    # 芯片类型错误 (优先检查，因为这通常导致Error 2)
    if "wrong --chip" in output_lower or "this chip is" in output_lower:
        actual_chip, expected_chip = extract_chip_info(output)

        if actual_chip and expected_chip:
            # 动态生成建议
            suggested_board = get_board_suggestion(actual_chip)
            current_board = extract_board_from_error(output)

            suggestions.append(f"🔧 芯片类型错误：项目配置为{expected_chip}，但设备是{actual_chip}")

            if current_board:
                suggestions.append(f"📝 将platformio.ini中的board从'{current_board}'改为'{suggested_board}'")
            else:
                suggestions.append(f"📝 修改platformio.ini中的board配置为{suggested_board}")

            suggestions.append(f"🔄 或者使用正确的{expected_chip}开发板")

            # 添加具体的配置示例
            suggestions.append(f"💡 配置示例：[env:myproject]\\nboard = {suggested_board}")
        else:
            # 通用建议
            suggestions.append("🔧 芯片类型不匹配：检查platformio.ini中的board配置")
            suggestions.append("📋 查看错误信息中的芯片类型，选择对应的board配置")

    # 串口问题
    elif return_code == 2 or "error 2" in output_lower or return_code == 1:
        if "could not automatically find serial port" in output_lower:
            suggestions.append("🔌 无法找到串口：检查设备连接")
            suggestions.append("💻 确认设备驱动已正确安装")
        else:
            suggestions.append("🔌 检查设备连接：确保ESP32通过USB连接到电脑")
            suggestions.append("🔄 尝试重新插拔USB线")

    # 权限问题
    elif "permission denied" in output_lower or "access denied" in output_lower:
        suggestions.append("🔐 权限问题：尝试以管理员身份运行")
        suggestions.append("🚫 关闭可能占用串口的程序")

    # 超时问题
    elif "timeout" in output_lower:
        suggestions.append("⏱️ 连接超时：检查USB线质量")
        suggestions.append("🔄 尝试按住ESP32的BOOT按钮再烧录")

    # 串口占用
    elif "could not open port" in output_lower:
        suggestions.append("🔌 串口被占用：关闭Arduino IDE、PlatformIO等程序")
        suggestions.append("💻 检查设备管理器中的串口驱动")

    # 编译错误
    elif return_code == 1 and ("error:" in output_lower or "failed" in output_lower):
        suggestions.append("🔨 编译错误：检查代码语法")
        suggestions.append("📁 确认所有依赖库已正确安装")

    if not suggestions:
        suggestions.append("🔍 请检查详细输出信息以了解具体错误")
        suggestions.append("📖 参考PlatformIO官方文档进行故障排除")

    return suggestions

project_blueprint = Blueprint('project_api', __name__)

# --- V2 新增：用于管理已同步的本地项目的内存字典 ---
# 在生产环境中，这应该被替换为数据库或Redis
SYNCED_LOCAL_PROJECTS = {}


# --- 文件分析与工作流相关的路由 ---

@project_blueprint.route('/analyze', methods=['POST'])
@token_required
def analyze_project_request():
    data = request.get_json()
    if not data or not data.get('raw_text'):
        return jsonify({"error": "raw_text field is required"}), 400
    try:
        structured_request = project_analyzer_service.analyze_requirement(
            user_id=g.current_user.id, raw_text=data['raw_text']
        )
        return jsonify(structured_request), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        print(f"ERROR in /projects/analyze: {e}")
        return jsonify({"error": f"Failed to analyze requirement: {str(e)}"}), 500


@project_blueprint.route('/sync-local', methods=['POST'])
@token_required
def sync_local_project():
    """【V2 新增】接收前端上传的本地项目zip包"""
    if 'project_zip' not in request.files:
        return jsonify({"error": "Missing 'project_zip' file in request"}), 400

    file = request.files['project_zip']

    # 为这个同步项目创建一个唯一的ID和临时工作区
    project_id = f"local-{uuid.uuid4()}"
    # 使用与云端工作流相同的根目录
    project_root = Path(__file__).resolve().parent.parent
    workspace_path = project_root / "temp_workspaces" / project_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    try:
        # 保存并解压zip文件
        zip_path = workspace_path / "project.zip"
        file.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(workspace_path)

        # 清理zip文件
        zip_path.unlink()

        # 存储ID和路径的映射关系
        SYNCED_LOCAL_PROJECTS[project_id] = str(workspace_path)

        print(f"Synced local project. ID: {project_id}, Path: {workspace_path}")
        return jsonify({"localProjectId": project_id, "message": "Project synced successfully"}), 201

    except Exception as e:
        # 如果出错，清理已创建的目录
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
        return jsonify({"error": f"Failed to process project zip: {str(e)}"}), 500


@project_blueprint.route('/analyze-syntax', methods=['POST'])
@token_required
def analyze_syntax():
    """【V5 简化重构版】"""
    data = request.get_json()
    if not data or 'code' not in data or 'language' not in data:
        return jsonify({"error": "请求体中缺少'code'或'language'字段"}), 400

    language = data.get('language')
    code = data.get('code')
    workflow_id = data.get('workflowId')
    local_project_id = data.get('localProjectId')

    analysis_result = {"success": True, "errors": []}
    workspace_path = None

    if language == 'cpp':
        # 尝试获取工作区路径
        if workflow_id:
            try:
                status = workflow_service.get_workflow_status(workflow_id)
                if status and 'latest_state' in status:
                    workspace_path = status['latest_state'].get('workspace_path')
            except Exception as e:
                print(f"无法为云端项目 {workflow_id} 获取工作区路径: {e}")
        elif local_project_id:
            workspace_path = SYNCED_LOCAL_PROJECTS.get(local_project_id)
            if workspace_path:
                # 实时更新被编辑的文件内容，以确保分析的是最新版本
                file_path_to_update = data.get('filePath')
                if file_path_to_update:
                    full_path = Path(workspace_path) / file_path_to_update
                    try:
                        full_path.parent.mkdir(parents=True, exist_ok=True)
                        full_path.write_text(code, encoding='utf-8')
                    except Exception as e:
                        print(f"无法更新同步的本地文件 {full_path}: {e}")

        # 调用统一的分析服务入口
        analysis_result = syntax_analyzer_service.analyze_cpp_code(code, workspace_path)

    elif language == 'python':
        analysis_result = syntax_analyzer_service.analyze_python_syntax(code)

    return jsonify(analysis_result), 200

# --- 项目模板相关的路由 (保持不变) ---
@project_blueprint.route('', methods=['POST'])
@token_required
def save_project():
    data = request.get_json()
    if not data or not data.get('name') or not data.get('config_json'):
        return jsonify({"error": "Missing project name or config_json"}), 400
    project = Project(name=data['name'], config_json=json.dumps(data['config_json']), owner=g.current_user)
    db.session.add(project)
    db.session.commit()
    return jsonify(project.to_dict()), 201


@project_blueprint.route('/<int:project_id>', methods=['GET'])
@token_required
def get_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=g.current_user.id).first_or_404()
    return jsonify(project.to_dict()), 200


@project_blueprint.route('', methods=['GET'])
@token_required
def list_projects():
    projects = Project.query.filter_by(user_id=g.current_user.id).order_by(Project.id.desc()).all()
    return jsonify([{'id': p.id, 'name': p.name} for p in projects]), 200


@project_blueprint.route('/<int:project_id>', methods=['DELETE'])
@token_required
def delete_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=g.current_user.id).first_or_404()
    db.session.delete(project)
    db.session.commit()
    return jsonify({"message": "项目模板删除成功"}), 200


@project_blueprint.route('/flash', methods=['POST'])
@token_required
def flash_firmware():
    """烧录固件到设备"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "请求体不能为空"}), 400

    workflow_id = data.get('workflowId')
    local_project_id = data.get('localProjectId')
    local_project_path = data.get('localProjectPath')  # 新增：直接传递本地项目路径

    workspace_path = None

    # 获取工作区路径
    if workflow_id:
        try:
            status = workflow_service.get_workflow_status(workflow_id)
            if status and 'latest_state' in status:
                workspace_path = status['latest_state'].get('workspace_path')
        except Exception as e:
            return jsonify({"error": f"无法获取云端项目工作区路径: {str(e)}"}), 500
    elif local_project_id:
        workspace_path = SYNCED_LOCAL_PROJECTS.get(local_project_id)
    elif local_project_path:
        # 新增：直接使用传递的本地项目路径
        # 构建完整路径
        project_root = Path(__file__).resolve().parent.parent
        if local_project_path.startswith('temp_workspaces/'):
            workspace_path = str(project_root / local_project_path)
        elif 'wf-' in local_project_path:
            workspace_path = str(project_root / "temp_workspaces" / local_project_path)
        else:
            return jsonify({"error": "不支持的本地项目路径"}), 400

    if not workspace_path or not os.path.exists(workspace_path):
        return jsonify({"error": "找不到项目工作区路径"}), 404

    # 检查是否是有效的PlatformIO项目
    platformio_ini = os.path.join(workspace_path, 'platformio.ini')
    if not os.path.exists(platformio_ini):
        return jsonify({"error": "不是有效的PlatformIO项目（缺少platformio.ini文件）"}), 400

    try:
        # 首先检查PlatformIO是否可用
        try:
            pio_check = subprocess.run(
                ["platformio", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            print(f"PlatformIO版本检查: 返回码={pio_check.returncode}, 输出={pio_check.stdout}")
            if pio_check.returncode != 0:
                return jsonify({"error": f"PlatformIO不可用: {pio_check.stderr}"}), 500
        except FileNotFoundError:
            return jsonify({"error": "PlatformIO未安装或不在PATH中"}), 500
        except subprocess.TimeoutExpired:
            return jsonify({"error": "PlatformIO版本检查超时"}), 500

        # 执行PlatformIO烧录命令，添加详细输出
        command = ["platformio", "run", "--target", "upload", "--verbose"]
        print(f"执行烧录命令: {' '.join(command)} 在目录: {workspace_path}")

        result = subprocess.run(
            command,
            cwd=workspace_path,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=300  # 5分钟超时
        )

        if result.returncode == 0:
            success_output = result.stdout or "烧录完成"
            print("=" * 60)
            print("🎉 PlatformIO烧录成功！")
            print(f"项目路径: {workspace_path}")
            print(f"执行时间: {result.args}")
            print("烧录输出:")
            print(success_output)
            print("=" * 60)
            return jsonify({
                "message": "烧录成功",
                "output": success_output
            }), 200
        else:
            # 合并stdout和stderr，获取完整输出
            full_output = ""
            if result.stdout:
                full_output += "STDOUT:\n" + result.stdout + "\n\n"
            if result.stderr:
                full_output += "STDERR:\n" + result.stderr + "\n\n"

            if not full_output:
                full_output = "未知错误 - 没有输出信息"

            print("=" * 60)
            print("❌ PlatformIO烧录失败！")
            print(f"项目路径: {workspace_path}")
            print(f"返回码: {result.returncode}")
            print("完整输出:")
            print(full_output)
            print("=" * 60)

            # 调试信息
            print(f"DEBUG: result.returncode = {result.returncode}")
            print(f"DEBUG: type(result.returncode) = {type(result.returncode)}")

            # 检查输出中是否包含Error 2，如果是则修正返回码
            actual_return_code = result.returncode
            if "error 2" in full_output.lower() or "*** [upload] error 2" in full_output.lower():
                print("DEBUG: Found 'Error 2' in output, correcting return code to 2")
                actual_return_code = 2

            # 提取关键错误信息
            key_errors = extract_key_errors(full_output)
            error_summary = "\n".join(key_errors) if key_errors else "未找到具体错误信息"

            # 分析常见错误并提供建议
            error_suggestions = analyze_flash_error(actual_return_code, full_output)

            return jsonify({
                "error": f"烧录失败 (返回码: {actual_return_code})",
                "output": full_output,  # 完整输出，供调试使用
                "key_errors": error_summary,  # 关键错误信息，供用户查看
                "suggestions": error_suggestions,
                "returncode": actual_return_code,
                "original_returncode": result.returncode  # 保留原始返回码用于调试
            }), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "烧录超时，请检查设备连接"}), 500
    except FileNotFoundError:
        return jsonify({"error": "找不到PlatformIO命令，请确保已正确安装PlatformIO"}), 500
    except Exception as e:
        return jsonify({"error": f"烧录过程中发生错误: {str(e)}"}), 500