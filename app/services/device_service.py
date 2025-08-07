# app/services/device_service.py
# -*- coding: utf-8 -*-

from app import db
from app.models import Device, User

def register_device(user: User, device_data: dict) -> Device:
    """
    为指定用户创建新设备，包含云平台和三元组信息。
    """
    new_device = Device(
        owner=user,
        nickname=device_data.get('nickname'),
        board_model=device_data.get('board_model'),
        # 【核心修改】从请求数据中获取云平台和三元组信息
        cloud_platform=device_data.get('cloud_platform', 'tuya'),
        cloud_product_id=device_data.get('cloud_product_id'),
        cloud_device_id=device_data.get('cloud_device_id'),
        cloud_device_secret=device_data.get('cloud_device_secret')
    )
    db.session.add(new_device)
    db.session.commit()
    return new_device

def get_user_devices(user: User):
    """获取指定用户的所有设备"""
    # 按id降序排序，让最新注册的设备显示在最前面
    return Device.query.filter_by(user_id=user.id).order_by(Device.id.desc()).all()
