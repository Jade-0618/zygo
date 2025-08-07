# app/services/project_analyzer_service.py
# -*- coding: utf-8 -*-

import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_core.output_parsers import JsonOutputParser

from app.services import device_service
from app.models import User

API_KEY = "a985545a-1c6b-4bf4-8956-8c93ffc2181f"
BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"

analyzer_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.1, api_key=API_KEY, base_url=BASE_URL)

def get_analyzer_prompt(raw_text: str, user_devices: list) -> str:
    device_context = "\\n".join(
        [f"- {d.nickname} (ID: {d.internal_device_id}, Model: {d.board_model})" for d in user_devices]
    )
    if not device_context:
        device_context = "用户当前未注册任何设备。"

    prompt = f"""
<Prompt>
    <Role>你是一位顶级的物联网解决方案架构师，擅长将复杂的项目需求分解为多个协作的设备任务。</Role>
    <Goal>你的任务是将用户涉及多个设备的、口语化的项目构想，转换成一个包含所有设备任务和它们之间通信关系的、结构化的JSON对象。</Goal>
    <Context>
        <UserRawRequest>{raw_text}</UserRawRequest>
        <UserRegisteredDevices>
        {device_context}
        </UserRegisteredDevices>
    </Context>
    <Instructions>
    1.  **识别项目全局信息**: 从用户请求中提取总体的 `project_name` (项目名称) 和 `project_description` (对整个多设备系统的描述)。
    2.  **识别并定义每个设备 (Device Tasks)**:
        * 在用户的请求中，识别出所有独立工作的物理设备 (例如 "大绿板", "小黑板", "网关")。
        * 为每一个识别出的设备创建一个独立的JSON对象，并放入 `device_tasks` 列表中。
        * 在每个设备对象中：
            * `device_role`: 填写用户描述中对该设备的角色称呼 (e.g., "光照采集端", "报警器")。
            * `internal_device_id`: 根据角色描述，从 `<UserRegisteredDevices>` 列表中选择最匹配的一个设备，将其ID填入。如果找不到匹配或列表为空，留空此字段。
            * `peripherals`: 识别并列出【只属于这个设备】的物理外设 (传感器、执行器等)，并推断其`model`和`pin` (如果引脚未提及，设为 "USER_INPUT_REQUIRED")。
            * `description`: 简要描述【这个设备自己】的核心职责。
    3.  **定义设备间通信 (Inter-Device Communication)**:
        * 分析设备任务之间的信息流动。
        * 在 `inter_device_communication` 列表中为每一条单向数据流创建一个对象。
        * 每个通信对象应包含：`source_device_role` (发送方角色名), `target_device_role` (接收方角色名), `data_description` (描述传输的数据内容), `protocol` (推断通信协议, 默认为 "MQTT")。
    4.  **格式化输出**: 你的最终输出必须是一个遵循下述格式的、不包含任何额外解释的、单一且有效的JSON对象。
    </Instructions>
    <OutputFormat>
    ```json
    {{
      "project_name": "多设备光照监控报警系统",
      "project_description": "一个由光照采集端和云端报警器组成的系统，当光照过强时通过云平台报警。",
      "device_tasks": [
        {{
          "device_role": "光照采集端",
          "internal_device_id": "device-uuid-of-green-board",
          "peripherals": [
            {{ "name": "光照传感器", "model": "BH1750", "pin": 34 }}
          ],
          "description": "使用BH1750传感器读取光照强度，并将数据发送给小黑板。"
        }},
        {{
          "device_role": "报警器",
          "internal_device_id": "device-uuid-of-black-board",
          "peripherals": [],
          "description": "接收来自大绿板的光照强度数据，如果强度高于50lux，就向云平台发送报警信息。"
        }}
      ],
      "inter_device_communication": [
        {{
          "source_device_role": "光照采集端",
          "target_device_role": "报警器",
          "data_description": "光照强度数值 (illumination value)",
          "protocol": "MQTT"
        }}
      ]
    }}
    ```
    </OutputFormat>
</Prompt>
"""
    return prompt

def analyze_requirement(user_id: int, raw_text: str) -> dict:
    user = User.query.get(user_id)
    if not user:
        raise ValueError("User not found")
    user_devices = device_service.get_user_devices(user)
    prompt = get_analyzer_prompt(raw_text, user_devices)
    parser = JsonOutputParser()
    chain = analyzer_model | parser
    try:
        structured_json = chain.invoke([HumanMessage(content=prompt)])
        if 'device_tasks' not in structured_json or not isinstance(structured_json['device_tasks'], list):
            raise ValueError("AI返回的JSON格式不正确，缺少'device_tasks'列表。")
        return structured_json
    except Exception as e:
        print(f"Error invoking LLM or parsing JSON: {e}")
        raise RuntimeError(f"Failed to get a valid JSON response from the analyzer model. Error: {str(e)}")


def analyze_inter_device_communication(device_tasks: list) -> dict:
    """
    【V2 修正后】一个专用的函数，仅根据设备任务列表分析通信关系，并能理解别名。
    """
    # 将设备任务列表格式化为文本，包含角色和昵称，供AI理解
    task_descriptions = "\\n".join(
        [f"- **Role**: {task.get('device_role', 'N/A')}, **Nickname**: {task.get('nickname', 'N/A')}, **Description**: {task.get('description', 'N/A')}" for task in device_tasks]
    )

    prompt = f"""
<Prompt>
    <Role>你是一位顶级的物联网系统架构师，专注于设备间的通信协议和数据流。</Role>
    <Goal>根据下面描述的设备任务列表，分析并定义它们之间所有必要的数据通信链路，请特别注意别名。</Goal>
    <Context>
        <DeviceTasksList>
        {task_descriptions}
        </DeviceTasksList>
    </Context>
    <Instructions>
    1.  **识别实体**: 列表中的每一项代表一个设备，它由唯一的 `Role` 标识。`Nickname` 是该设备的一个别名。
    2.  **解析别名**: 在分析描述时，请理解一个 `Nickname` (例如: "大绿板") 和它对应的 `Role` (例如: "光照采集端") 指的是【完全相同】的实体。不要为它们创建重复的通信路径。
    3.  **分析数据流**: 阅读每个设备的描述，判断哪个设备是数据源，哪个是目标。
    4.  **使用规范角色名**: 在你的最终输出中，必须使用设备的 `Role` 作为 `source_device_role` 和 `target_device_role` 的标识符。不要使用 `Nickname`。
    5.  **创建通信对象**: 为每一条识别出的单向数据流，创建一个包含 `source_device_role`, `target_device_role`, `data_description`, 和 `protocol` (默认为 'MQTT') 的JSON对象。
    6.  **最终格式**: 你的输出必须是一个只包含一个key "inter_device_communication" 的JSON对象，其value是一个包含所有通信对象的列表。如果设备间无需通信，则返回空列表。
    </Instructions>
    <OutputFormat>
    ```json
    {{
      "inter_device_communication": [
        {{
          "source_device_role": "光照采集端",
          "target_device_role": "报警器",
          "data_description": "光照强度数值 (illumination value)",
          "protocol": "MQTT"
        }}
      ]
    }}
    ```
    </OutputFormat>
</Prompt>
"""
    parser = JsonOutputParser()
    chain = analyzer_model | parser
    try:
        result = chain.invoke([HumanMessage(content=prompt)])
        return result
    except Exception as e:
        print(f"Error invoking communication analyzer: {e}")
        raise RuntimeError("Failed to get a valid communication plan from the model.")
