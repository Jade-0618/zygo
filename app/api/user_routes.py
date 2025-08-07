# app/api/user_routes.py
# -*- coding: utf-8 -*-

from flask import Blueprint, request, jsonify, g
from app.services import user_service
from .device_routes import token_required

user_blueprint = Blueprint('user_api', __name__)

# 【核心修改】将原来的一个函数拆分为两个，分别处理 GET 和 PUT
@user_blueprint.route('/config', methods=['GET'])
@token_required
def get_config():
    """获取当前登录用户的配置信息。"""
    # g.current_user 是由 @token_required 装饰器注入的
    config = user_service.get_user_config(g.current_user)
    return jsonify(config), 200


@user_blueprint.route('/config', methods=['PUT'])
@token_required
def update_config():
    """更新当前登录用户的配置信息。"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    # g.current_user 是由 @token_required 装饰器注入的
    user_service.update_user_config(g.current_user, data)

    return jsonify({"message": "Configuration updated successfully."}), 200
