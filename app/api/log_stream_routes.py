# app/api/log_stream_routes.py
# -*- coding: utf-8 -*-

import time
from flask import Blueprint, Response, stream_with_context
from app.models import WorkflowState
import json

log_stream_blueprint = Blueprint('log_stream_api', __name__)


@log_stream_blueprint.route('/<workflow_id>')
def stream(workflow_id):
    """
    为指定的工作流ID建立一个Server-Sent Events (SSE)连接，
    通过轮询数据库来流式传输日志。
    """

    def generate_logs():
        last_sent_length = 0
        try:
            while True:
                # 从数据库获取当前工作流的状态和日志
                workflow = WorkflowState.query.get(workflow_id)
                if not workflow:
                    # 如果工作流被删除或不存在，则结束流
                    yield f"data: {{\"error\": \"Workflow not found.\"}}\n\n"
                    break

                current_logs = workflow.logs
                if len(current_logs) > last_sent_length:
                    # 如果有新的日志，只发送增量部分
                    new_log_chunk = current_logs[last_sent_length:]
                    # 按行发送，以获得更好的前端体验
                    for line in new_log_chunk.strip().split('\n'):
                        yield f"data: {{\"log\": \"{line}\"}}\n\n"
                    last_sent_length = len(current_logs)

                # 检查工作流是否已结束
                state = json.loads(workflow.state_json)
                if state.get('status') in ['COMPLETED', 'FAILED']:
                    yield f"data: {{\"status\": \"{state.get('status')}\"}}\n\n"
                    break

                # 等待一段时间再进行下一次轮询
                time.sleep(1)  # 1秒轮询间隔
        except Exception as e:
            print(f"Log stream for {workflow_id} error: {e}")
            yield f"data: {{\"error\": \"An internal error occurred.\"}}\n\n"

    return Response(stream_with_context(generate_logs()), mimetype='text/event-stream')
