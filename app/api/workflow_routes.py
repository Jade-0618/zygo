# app/api/workflow_routes.py
# -*- coding: utf-8 -*-

import shutil
from pathlib import Path # 【核心修正】添加了这一行导入
from flask import Blueprint, request, jsonify, g
from app.services import workflow_service
from .device_routes import token_required

workflow_blueprint = Blueprint('workflow_api', __name__)


@workflow_blueprint.route('', methods=['POST'])
@token_required
def create_workflow():
    """
    【V3 修正后】接收一个包含多设备任务的项目配置，并启动工作流。
    """
    data = request.get_json()
    if not data or not data.get('device_tasks'):
        return jsonify({"error": "请求体中必须包含 'device_tasks' 列表。"}), 400

    try:
        initial_status = workflow_service.start_workflow(g.current_user.id, data)
        return jsonify(initial_status), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Internal server error: {e}"}), 500


@workflow_blueprint.route('/<workflow_id>', methods=['GET'])
@token_required
def get_status(workflow_id):
    try:
        status = workflow_service.get_workflow_status(workflow_id)
        return jsonify(status), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@workflow_blueprint.route('/history', methods=['GET'])
@token_required
def get_history():
    """获取当前用户的所有工作流历史记录。"""
    history = []
    with workflow_service.WORKFLOW_LOCK:
        for wf_id, wf_data in workflow_service.WORKFLOWS.items():
            if wf_data.get('latest_state', {}).get('user_id') == g.current_user.id:
                history.append({
                    "workflow_id": wf_id,
                    "project_name": wf_data.get('latest_state', {}).get('project_name', '未命名项目'),
                    "status": wf_data.get('status', 'UNKNOWN'),
                })
    history.sort(key=lambda x: x['workflow_id'], reverse=True)
    return jsonify(history), 200


@workflow_blueprint.route('/<workflow_id>/actions', methods=['POST'])
@token_required
def perform_action(workflow_id):
    data = request.get_json()
    if not data or not data.get('action'):
        return jsonify({"error": "Action not specified"}), 400

    try:
        workflow_service.post_workflow_action(workflow_id, data)
        return jsonify({"message": "Action accepted"}), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@workflow_blueprint.route('/<workflow_id>/files', methods=['GET'])
@token_required
def list_files(workflow_id):
    path = request.args.get('path')
    try:
        if path:
            content = workflow_service.get_file_content(workflow_id, path)
            return jsonify({"path": path, "content": content}), 200
        else:
            tree = workflow_service.get_file_tree(workflow_id)
            return jsonify(tree), 200
    except FileNotFoundError as e:
        # 捕获明确的“文件未找到”错误
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        # 【核心修正】捕获所有其他可能的异常 (例如权限问题, 字典key不存在等)
        # 打印详细错误到后台日志，并向前台返回一个结构化的错误信息
        print(f"ERROR during file access for workflow '{workflow_id}': {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"获取文件列表时发生内部错误: {str(e)}"}), 500

@workflow_blueprint.route('/<workflow_id>/files', methods=['PUT'])
@token_required
def update_file(workflow_id):
    path = request.args.get('path')
    data = request.get_json()
    if not path or not data or 'content' not in data:
        return jsonify({"error": "Missing path or content"}), 400

    try:
        workflow_service.save_file_content(workflow_id, path, data['content'])
        return jsonify({"message": f"File '{path}' saved successfully."}), 200
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 404

@workflow_blueprint.route('/<workflow_id>', methods=['DELETE'])
@token_required
def delete_workflow(workflow_id):
    """【新增】删除一个工作流及其所有相关文件。"""
    with workflow_service.WORKFLOW_LOCK:
        workflow = workflow_service.WORKFLOWS.get(workflow_id)
        if not workflow:
            return jsonify({"error": "Workflow not found."}), 404

        if workflow.get('latest_state', {}).get('user_id') != g.current_user.id:
            return jsonify({"error": "Permission denied."}), 403

        workspace_path_str = workflow.get('latest_state', {}).get('workspace_path')
        del workflow_service.WORKFLOWS[workflow_id]

    if workspace_path_str:
        try:
            workspace_path = Path(workspace_path_str)
            if workspace_path.exists() and workspace_path.is_dir():
                shutil.rmtree(workspace_path)
        except Exception as e:
            print(f"Error deleting workspace for {workflow_id}: {e}")
            return jsonify({"message": f"Workflow record deleted, but failed to delete files: {e}"}), 500

    return jsonify({"message": "Workflow and all associated files deleted successfully."}), 200
