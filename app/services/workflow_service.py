# app/services/workflow_service.py
# -*- coding: utf-8 -*-

import threading
import uuid
import time
from pathlib import Path
from langgraph.graph import END
from flask import current_app
import json
import traceback
from sqlalchemy import text  # 核心导入: 用于执行原生SQL以实现原子更新

# 核心修改: 导入数据库模型和实例
from app.langgraph_def.graph_builder import build_graph
from app.langgraph_def.agent_state import AgentState, WorkflowStep
from app.models import Device, WorkflowState, User
from app import db

# 核心重构: 移除内存字典，改为延迟加载图
_GRAPH = None
_GRAPH_LOCK = threading.Lock()

# 【兼容性修正】重新添加 WORKFLOWS 和 WORKFLOW_LOCK 以解决旧模块的 ImportError
# 注意：这些变量不再用于主工作流状态管理，仅为兼容 log_stream_routes.py。
WORKFLOWS = {}
WORKFLOW_LOCK = threading.Lock()

# 为节点ID提供一个友好的UI显示名称映射
NODE_FRIENDLY_NAMES = {
    "master_router": "总路由",
    "device_dispatcher": "设备分发",
    "module_architect": "模块规划",
    "module_dispatcher": "任务分发",
    "api_designer": "API设计",
    "developer": "代码生成与修复",
    "integrator": "代码集成",
    "test_plan_designer": "测试规划",
    "deployment_and_verification": "准备工作区",
    "compile_node": "编译固件",
    "pre_deployment_pause": "等待部署",
    "usb_upload_node": "USB部署",
    "ota_deployment_node": "OTA部署",
    "deploy_and_verify_node": "部署与验证",
    "dp_extractor": "功能点提取",
    "resume_router": "恢复流程"
}


def get_graph():
    """
    延迟初始化函数，确保昂贵的图编译操作只在应用生命周期中执行一次。
    """
    global _GRAPH
    if _GRAPH is None:
        with _GRAPH_LOCK:
            if _GRAPH is None:
                print("--- [System Startup] Compiling workflow graph for the first time... ---")
                _GRAPH = build_graph()
                print("--- [System Startup] Graph compilation complete. ---")
    return _GRAPH


def find_step(steps: list, step_id: str) -> dict | None:
    """在步骤列表中通过ID查找特定步骤。"""
    return next((s for s in steps if s['id'] == step_id), None)


# --- 核心重构: 数据库状态管理辅助函数 ---

def _load_state(workflow_id: str) -> dict | None:
    """从数据库加载并反序列化工作流状态。"""
    record = WorkflowState.query.get(workflow_id)
    if record:
        return json.loads(record.state_json)
    return None


def _save_state(workflow_id: str, state_data: dict):
    """序列化并保存工作流状态到数据库。"""
    record = WorkflowState.query.get(workflow_id)
    state_json_str = json.dumps(state_data)
    if record:
        record.state_json = state_json_str
    else:
        record = WorkflowState(workflow_id=workflow_id, state_json=state_json_str)
        db.session.add(record)
    db.session.commit()


def _delete_state(workflow_id: str):
    """从数据库删除工作流状态。"""
    record = WorkflowState.query.get(workflow_id)
    if record:
        db.session.delete(record)
        db.session.commit()


def _log(workflow_id: str, message: str):
    """
    【核心新增】将日志消息附加到数据库记录中，并同时在终端打印。
    """
    try:
        timestamp = time.strftime('%H:%M:%S', time.localtime())
        log_line_for_print = f"[{timestamp}] {message}"
        log_line_for_db = f"{log_line_for_print}\n"

        # 1. 立即在终端打印，用于实时调试
        print(log_line_for_print)

        # 2. 使用 SQLAlchemy Core API 以确保在多线程环境下的原子性追加操作
        stmt = (
            text("UPDATE workflow_states SET logs = logs || :log_line WHERE workflow_id = :wid")
        )
        db.session.execute(stmt, {"log_line": log_line_for_db, "wid": workflow_id})
        db.session.commit()
    except Exception as e:
        print(f"FATAL ERROR: Failed to write log to database for {workflow_id}: {e}")
        db.session.rollback()


# --- 重构后的服务函数 ---

def _run_graph_in_thread(app, workflow_id: str, initial_state: AgentState):
    """
    【V3.3 架构重构版】在后台线程中执行LangGraph工作流。
    此版本拥有一个更健壮、更符合逻辑的状态更新循环。
    """
    with app.app_context():
        try:
            graph_to_run = get_graph()
            config = {"recursion_limit": 100, "configurable": {"thread_id": workflow_id}}

            # 在图开始前，我们并不知道第一个节点是什么，所以我们让循环来处理第一个节点的启动状态

            for step in graph_to_run.stream(initial_state, config):
                # --- 1. 健壮地解析 stream 的每一步 ---
                # stream 的产物是一个字典，key是节点名，value是该节点的返回状态更新
                if not isinstance(step, dict) or not step:
                    continue

                try:
                    # 使用 list(step.items())[0] 来安全地获取第一个键值对
                    current_node_id, state_update_from_node = list(step.items())[0]
                except IndexError:
                    continue  # 如果是空字典，则跳过

                # --- 2. 核心保护：防止 'NoneType' 错误 ---
                # 如果节点的返回值为 None，我们将其视为空字典，避免后续操作崩溃。
                if state_update_from_node is None:
                    state_update_from_node = {}

                # --- 3. 加载最新的工作流数据 ---
                workflow_data = _load_state(workflow_id)
                if not workflow_data:
                    print(f"工作流 {workflow_id} 状态从数据库中消失，线程中止。")
                    break

                # --- 4. 实现更清晰的状态更新逻辑 ---
                latest_state = workflow_data['latest_state']
                steps_list = latest_state['workflow_steps']
                latest_state.update(state_update_from_node)

                # --- [最终修正] 在设备分发节点完成后，打印设备切换的分隔符 ---
                if current_node_id == "device_dispatcher":
                    new_device_task = latest_state.get('current_device_task')
                    if new_device_task:
                        device_role = new_device_task.get('device_role', 'Unknown Device')
                        _log(workflow_id, f"\\n========================================================")
                        _log(workflow_id, f"===== 开始处理设备: {device_role} =====")
                        _log(workflow_id, f"========================================================")
                # --- 修正结束 ---

                # 找到刚刚运行完成的节点
                completed_step = find_step(steps_list, current_node_id)
                if completed_step:
                    # 如果它之前是 'running'，现在更新它的最终状态
                    if completed_step['status'] == 'running' or completed_step['status'] == 'pending':
                        completed_step['end_time'] = time.time()
                        feedback = state_update_from_node.get('feedback', '')

                        if "FAIL:" in feedback:
                            completed_step['status'] = 'failed'
                            # 将详细错误信息记录到步骤日志
                            completed_step['log'] = feedback.split('FAIL:', 1)[-1].strip()
                            _log(workflow_id, f"步骤 '{completed_step['name']}' FAILED.")
                        else:
                            completed_step['status'] = 'completed'
                            _log(workflow_id, f"步骤 '{completed_step['name']}' 已完成.")

                        # 如果有产出物，也记录下来 (可选)
                        if 'output' in state_update_from_node:
                            completed_step['output'] = str(state_update_from_node['output'])

                # d) 更新工作流的总体状态
                if current_node_id == "pre_deployment_pause":
                    workflow_data['status'] = "PAUSED"
                elif current_node_id == END or current_node_id == "__end__":
                    # 只有在图自然结束后才标记为COMPLETED
                    if workflow_data['status'] != "PAUSED":
                        workflow_data['status'] = "COMPLETED"
                else:
                    workflow_data['status'] = "RUNNING"

                # 找到下一个将要运行的节点并标记为 'running' (这是一个最佳实践，但较难实现)
                # 为了简化，我们只在日志中打印节点的开始信息
                # _log(workflow_id, f"步骤 '{next_node_name}' 已开始.")

                # --- 6. 保存更新后的状态 ---
                workflow_data['latest_state'] = latest_state
                _save_state(workflow_id, workflow_data)

            # --- 7. 循环结束后的最终处理 ---
            # 循环结束后，再次加载状态，检查是否需要更新最终状态
            final_workflow_data = _load_state(workflow_id)
            if final_workflow_data and final_workflow_data['status'] == "RUNNING":
                final_workflow_data['status'] = 'COMPLETED'
                _save_state(workflow_id, final_workflow_data)
                _log(workflow_id, "工作流 COMPLETED.")

        except Exception as e:
            # 异常处理逻辑保持不变
            error_message = f"工作流线程 {workflow_id} 崩溃: {e}"
            print(error_message)
            traceback.print_exc()

            workflow_data = _load_state(workflow_id)
            if workflow_data:
                workflow_data['status'] = "FAILED"
                steps_list = workflow_data['latest_state']['workflow_steps']
                # 查找最后一个状态为 'running' 的步骤并标记为失败
                running_step = next((s for s in steps_list if s['status'] == 'running'), None)
                if running_step:
                    running_step['status'] = 'failed'
                    error_log_content = f"ERROR: {str(e)}\n{traceback.format_exc()}"
                    running_step['log'] = error_log_content
                    running_step['end_time'] = time.time()
                    _log(workflow_id, f"步骤 '{running_step['name']}' FAILED.")
                _save_state(workflow_id, workflow_data)


def start_workflow(user_id: int, request_data: dict) -> dict:
    """启动一个新的工作流，并将初始状态存入数据库。"""
    workflow_id = f"wf-{uuid.uuid4()}"
    device_tasks_from_request = request_data.get('device_tasks', [])
    if not device_tasks_from_request:
        raise ValueError("Request must contain a list of device_tasks.")

    for task in device_tasks_from_request:
        device_id = task.get('internal_device_id')
        if not device_id:
            raise ValueError(f"Device task for role '{task.get('device_role')}' is missing an internal_device_id.")
        device = Device.query.filter_by(internal_device_id=device_id, user_id=user_id).first()
        if not device:
            raise ValueError(f"Device with ID {device_id} not found or does not belong to the user.")
        task['board'] = device.board_model

    project_root = Path(__file__).resolve().parent.parent
    workspace_path = project_root / "temp_workspaces" / workflow_id
    workspace_path.mkdir(parents=True, exist_ok=True)

    # 【性能优化修正】确保共享缓存目录在工作流开始时就存在
    cache_path = project_root / "temp_workspaces" / ".build_cache"
    cache_path.mkdir(exist_ok=True)
    print(f"--- [Workflow Start] Ensured shared build cache exists at: {cache_path} ---")

    initial_steps: list[WorkflowStep] = []
    for node_id in NODE_FRIENDLY_NAMES.keys():
        initial_steps.append({
            "id": node_id,
            "name": NODE_FRIENDLY_NAMES.get(node_id, node_id.replace("_", " ").title()),
            "status": "pending", "log": "", "start_time": 0.0, "end_time": 0.0, "output": None,
        })

    communication_plan = request_data.get('inter_device_communication', [])

    # 从数据库加载用户和设备信息以填充初始状态
    user = User.query.get(user_id)
    initial_wifi_ssid = user.wifi_ssid if user else ""
    initial_wifi_password = user.wifi_password if user else ""

    initial_state = AgentState(
        workflow_id=workflow_id, user_id=user_id,
        project_name=request_data.get('project_name', '未命名多设备项目'),
        status="RUNNING", workflow_steps=initial_steps,
        user_input=request_data.get('project_description', ''),
        device_tasks_queue=device_tasks_from_request,
        system_plan={"communication": communication_plan},
        workspace_path=str(workspace_path.resolve()),
        available_actions=[], current_device_task=None, current_api_spec=None,
        module_tasks=[], current_module_task=None, completed_modules={},
        feedback="", project_files={}, test_plan=None, original_module_plan=None,
        build_dir="", firmware_path=None, deployment_choice=None,
        dp_info_list=[], faulty_module=None, user_action=None,
        # 填充初始的WiFi信息
        wifi_ssid=initial_wifi_ssid,
        wifi_password=initial_wifi_password,
        cloud_product_id=None,
        cloud_device_id=None,
        cloud_device_secret=None
    )

    workflow_data = {"status": "STARTING", "latest_state": initial_state}
    _save_state(workflow_id, workflow_data)
    _log(workflow_id, f"New workflow created for project: {initial_state['project_name']}")

    app = current_app._get_current_object()
    thread = threading.Thread(target=_run_graph_in_thread, args=(app, workflow_id, initial_state))
    thread.daemon = True
    thread.start()

    return {"workflow_id": workflow_id, "status": "RUNNING", "workflow_steps": initial_steps, "available_actions": []}

def get_workflow_status(workflow_id: str) -> dict:
    """从数据库获取工作流状态。"""
    workflow_data = _load_state(workflow_id)
    if not workflow_data:
        raise ValueError("Workflow not found.")

    status = workflow_data['status']
    state = workflow_data['latest_state']

    available_actions = []
    if status == "PAUSED":
        available_actions = state.get('available_actions', [])
        if not available_actions:
            available_actions.extend(["DEPLOY_USB", "DEPLOY_OTA"])

    return {"workflow_id": workflow_id, "status": status, "workflow_steps": state.get('workflow_steps', []),
            "available_actions": available_actions}


def post_workflow_action(workflow_id: str, action_data: dict):
    """接收用户操作，更新数据库状态，并启动恢复线程。"""
    action = action_data.get("action")
    workflow_data = _load_state(workflow_id)

    if not workflow_data:
        raise ValueError("Workflow not found.")
    if workflow_data['status'] != 'PAUSED':
        raise ValueError(f"Workflow is in '{workflow_data['status']}' state, cannot perform actions.")

    state_to_resume = workflow_data['latest_state']
    state_to_resume['user_action'] = action
    state_to_resume['deployment_choice'] = "usb" if action == "DEPLOY_USB" else "ota"

    workflow_data['status'] = "RUNNING"
    workflow_data['latest_state'] = state_to_resume
    _save_state(workflow_id, workflow_data)
    _log(workflow_id, f"Action '{action}' received. Resuming graph execution.")

    app = current_app._get_current_object()
    thread = threading.Thread(target=_run_graph_in_thread, args=(app, workflow_id, state_to_resume))
    thread.daemon = True
    thread.start()


# --- 文件操作函数 (保持不变) ---
def get_file_tree(workflow_id: str) -> list:
    workflow_data = _load_state(workflow_id)
    if not workflow_data:
        raise ValueError("Workflow not found.")

    workspace_path_str = workflow_data['latest_state'].get('workspace_path')
    if not workspace_path_str: return []

    workspace_path = Path(workspace_path_str)
    if not workspace_path.exists(): return []

    def build_tree(dir_path: Path):
        tree = []
        for item in sorted(dir_path.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
            if item.name.startswith('.'): continue
            node = {"name": item.name, "path": str(item.relative_to(workspace_path)).replace("\\", "/")}
            if item.is_dir():
                node["type"] = "folder"
                node["children"] = build_tree(item)
            else:
                node["type"] = "file"
            tree.append(node)
        return tree

    return build_tree(workspace_path)


def get_file_content(workflow_id: str, file_path: str) -> str:
    workflow_data = _load_state(workflow_id)
    if not workflow_data: raise ValueError("Workflow not found.")

    workspace_path = Path(workflow_data['latest_state']['workspace_path'])
    full_path = (workspace_path / file_path).resolve()

    if not str(full_path).startswith(str(workspace_path.resolve())):
        raise ValueError("Access denied: path is outside the workspace.")

    if not full_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    return full_path.read_text(encoding='utf-8')


def save_file_content(workflow_id: str, file_path: str, content: str):
    workflow_data = _load_state(workflow_id)
    if not workflow_data: raise ValueError("Workflow not found.")

    workspace_path = Path(workflow_data['latest_state']['workspace_path'])
    full_path = (workspace_path / file_path).resolve()

    if not str(full_path).startswith(str(workspace_path.resolve())):
        raise ValueError("Access denied: path is outside the workspace.")

    if not full_path.exists():
        raise FileNotFoundError(f"File not found, cannot save: {file_path}")

    full_path.write_text(content, encoding='utf-8')
