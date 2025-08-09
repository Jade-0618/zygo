# app/__init__.py
# -*- coding: utf-8 -*-

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # <-- 新增导入
from config import config

db = SQLAlchemy()
migrate = Migrate()  # <-- 新增实例化


def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)
    migrate.init_app(app, db)  # <-- 新增初始化

    # 注册蓝图 (保持不变)
    from .api.auth_routes import auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/api/v1/auth')

    from .api.device_routes import device_blueprint
    app.register_blueprint(device_blueprint, url_prefix='/api/v1/devices')

    from .api.workflow_routes import workflow_blueprint
    app.register_blueprint(workflow_blueprint, url_prefix='/api/v1/workflows')

    from .api.project_routes import project_blueprint
    app.register_blueprint(project_blueprint, url_prefix='/api/v1/projects')

    from .api.user_routes import user_blueprint
    app.register_blueprint(user_blueprint, url_prefix='/api/v1/user')

    from .api.log_stream_routes import log_stream_blueprint
    app.register_blueprint(log_stream_blueprint, url_prefix='/api/v1/stream')

    from .api.mqtt_routes import mqtt_blueprint
    app.register_blueprint(mqtt_blueprint, url_prefix='/api/v1/mqtt')

    return app
