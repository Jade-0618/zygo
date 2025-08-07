# app/api/project_routes.py
# -*- coding: utf-8 -*-

import shutil
import tempfile
import zipfile
import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, g
from app.services import project_analyzer_service, workflow_service, syntax_analyzer_service
from .device_routes import token_required
from app.models import Project
import json
from app import db

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