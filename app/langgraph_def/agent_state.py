# app/langgraph_def/agent_state.py
# -*- coding: utf-8 -*-

from typing import TypedDict, List, Dict, Optional, Any


from typing import TypedDict, List, Dict, Optional, Any


class WorkflowStep(TypedDict):
    """Defines the structure for a single step in the workflow dashboard."""
    id: str  # The node's unique ID, e.g., "module_architect"
    name: str  # The user-friendly name for the UI, e.g., "模块规划"
    status: str  # 'pending', 'running', 'completed', 'failed'
    log: str  # The log output from this step
    start_time: float
    end_time: float
    output: Optional[str]  # 新增：用于存储步骤的核心产出物


class AgentState(TypedDict):
    """
    Defines the entire state of the workflow graph, adapted for a visual dashboard.
    """
    # --- V3 API and Dashboard Fields ---
    workflow_id: str
    user_id: Optional[int]
    status: str  # Overall workflow status (RUNNING, PAUSED, COMPLETED, FAILED)
    workflow_steps: List[WorkflowStep]  # New structured list for dashboard visualization
    available_actions: List[str]
    workspace_path: str
    user_action: Optional[str]

    # 【核心修改】新增项目名称字段
    project_name: str

    # --- 【核心修正】新增用于传递数据库上下文的字段 ---
    wifi_ssid: Optional[str]
    wifi_password: Optional[str]
    cloud_product_id: Optional[str]
    cloud_device_id: Optional[str]
    cloud_device_secret: Optional[str]


    # --- Core Fields from original logic ---
    user_input: str
    system_plan: Optional[Any]
    device_tasks_queue: List[Any]
    current_device_task: Optional[Any]
    current_api_spec: Optional[str]
    module_tasks: List[Any]
    current_module_task: Optional[Any]
    completed_modules: Dict[str, Any]
    feedback: str
    project_files: Dict[str, Dict[str, str]]
    test_plan: Optional[Dict]
    original_module_plan: Optional[List[Any]]
    build_dir: str
    firmware_path: Optional[str]
    deployment_choice: Optional[str]
    dp_info_list: List[Dict[str, str]]
    faulty_module: Optional[str]

