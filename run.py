# run.py

import os
from dotenv import load_dotenv
from app import create_app, db

# 加载环境变量
load_dotenv()
# 【核心修正】在这里导入 Project 和新增的 WorkflowState 模型
from app.models import User, Device, Project, WorkflowState, MqttLog
from app.services.mqtt_service import mqtt_monitor
from flask import render_template

# 使用开发环境配置创建应用
app = create_app(os.getenv('FLASK_CONFIG') or 'development')

# 处理根路径请求，返回前端页面
@app.route('/')
def index():
    return render_template('index.html')

@app.shell_context_processor
def make_shell_context():
    # 为flask shell提供上下文，同样加入 Project 和 MqttLog
    return dict(db=db, User=User, Device=Device, Project=Project, MqttLog=MqttLog)

# 创建一个自定义的Flask CLI命令来初始化数据库
@app.cli.command("init-db")
def init_db_command():
    """创建所有数据库表。"""
    db.create_all()
    print('Initialized the database and created all tables.')

if __name__ == '__main__':
    # 启动MQTT监控服务（可选，如果不需要MQTT功能可以注释掉）
    try:
        with app.app_context():
            mqtt_monitor.start_monitoring()
    except Exception as e:
        print(f"MQTT服务启动失败（可忽略）: {e}")

    # 添加 use_reloader=False 来禁用文件监控和自动重启
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
