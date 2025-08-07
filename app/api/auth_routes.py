# app/api/auth_routes.py
# -*- coding: utf-8 -*-

from flask import Blueprint, request, jsonify
from app.services import auth_service

# 创建一个蓝图对象
auth_blueprint = Blueprint('auth_api', __name__)


@auth_blueprint.route('/register', methods=['POST'])
def register():
    """用户注册接口"""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "缺少用户名或密码"}), 400

    user, message = auth_service.register_user(data['username'], data['password'])
    if not user:
        return jsonify({"error": message}), 409  # 409 Conflict

    return jsonify({"message": message, "user_id": user.id}), 201


@auth_blueprint.route('/login', methods=['POST'])
def login():
    """用户登录接口"""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "缺少用户名或密码"}), 400

    user = auth_service.verify_user(data['username'], data['password'])
    if not user:
        return jsonify({"error": "用户名或密码错误"}), 401

    # 生成Token
    token = auth_service.generate_auth_token(user.id)

    # 遵循API规约返回Token和用户信息
    return jsonify({
        "access_token": token,
        "user_info": {
            "id": user.id,
            "username": user.username
        }
    }), 200