# app/api/device_routes.py
# -*- coding: utf-8 -*-

from functools import wraps
from flask import Blueprint, request, jsonify, g
from app.services import device_service, auth_service
from app.models import User, Device
from app import db  # 导入db实例

device_blueprint = Blueprint('device_api', __name__)


# --- Token验证装饰器 ---
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'error': '未提供认证Token'}), 401

        user = auth_service.verify_auth_token(token)
        if not user:
            return jsonify({'error': 'Token无效或已过期'}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated_function


@device_blueprint.route('', methods=['POST'])
@token_required
def register_device():
    """注册新设备接口"""
    data = request.get_json()
    if not data or not data.get('nickname') or not data.get('board_model'):
        return jsonify({"error": "缺少必要的设备信息"}), 400

    device = device_service.register_device(g.current_user, data)

    if not device:
        return jsonify({"error": "设备注册失败"}), 500

    return jsonify({
        "message": "设备注册成功",
        "device": {
            "internal_device_id": device.internal_device_id,
            "nickname": device.nickname,
            "board_model": device.board_model
        }
    }), 201


@device_blueprint.route('', methods=['GET'])
@token_required
def get_devices():
    """获取当前用户的所有设备列表"""
    user_devices = device_service.get_user_devices(g.current_user)

    devices_list = [{
        "internal_device_id": dev.internal_device_id,
        "nickname": dev.nickname,
        "board_model": dev.board_model,
        "cloud_platform": dev.cloud_platform,
        "cloud_product_id": dev.cloud_product_id,
        "cloud_device_id": dev.cloud_device_id,
        "cloud_device_secret": dev.cloud_device_secret,
        # 【核心修改】在API响应中包含外设列表
        # dev.peripherals 会自动调用模型中的getter方法
        "peripherals": dev.peripherals
    } for dev in user_devices]

    return jsonify(devices_list), 200


# 【核心修改】更新设备信息的API
@device_blueprint.route('/<internal_device_id>', methods=['PUT'])
@token_required
def update_device(internal_device_id):
    """更新指定设备的信息"""
    device = Device.query.filter_by(internal_device_id=internal_device_id, user_id=g.current_user.id).first_or_404()
    data = request.get_json()
    if not data:
        return jsonify({"error": "请求体不能为空"}), 400

    # 更新设备的基本信息
    device.nickname = data.get('nickname', device.nickname)
    device.board_model = data.get('board_model', device.board_model)
    device.cloud_platform = data.get('cloud_platform', device.cloud_platform)
    device.cloud_product_id = data.get('cloud_product_id', device.cloud_product_id)
    device.cloud_device_id = data.get('cloud_device_id', device.cloud_device_id)
    device.cloud_device_secret = data.get('cloud_device_secret', device.cloud_device_secret)

    # 【核心修改】如果请求数据中包含 'peripherals'，则更新它
    if 'peripherals' in data:
        # device.peripherals 会自动调用模型中的setter方法，处理JSON序列化
        device.peripherals = data.get('peripherals')

    db.session.commit()
    return jsonify({"message": "设备信息更新成功"}), 200


# 【新增】删除设备的API
@device_blueprint.route('/<internal_device_id>', methods=['DELETE'])
@token_required
def delete_device(internal_device_id):
    """删除指定设备"""
    device = Device.query.filter_by(internal_device_id=internal_device_id, user_id=g.current_user.id).first_or_404()
    db.session.delete(device)
    db.session.commit()
    return jsonify({"message": "设备删除成功"}), 200
