# app/services/user_service.py
# -*- coding: utf-8 -*-

from app import db
from app.models import User


def update_user_config(user: User, config_data: dict) -> User:
    """
    更新指定用户的配置信息 (wifi_ssid, wifi_password).

    :param user: 当前登录的用户对象.
    :param config_data: 包含待更新配置的字典.
    :return: 更新后的用户对象.
    """
    if 'wifi_ssid' in config_data:
        user.wifi_ssid = config_data['wifi_ssid']

    if 'wifi_password' in config_data:
        user.wifi_password = config_data['wifi_password']

    db.session.commit()

    return user


# 【新增】获取用户配置的函数
def get_user_config(user: User) -> dict:
    """
    获取指定用户的配置信息。

    :param user: 当前登录的用户对象。
    :return: 包含用户配置的字典。
    """
    return {
        "wifi_ssid": user.wifi_ssid,
        "wifi_password": user.wifi_password
    }
