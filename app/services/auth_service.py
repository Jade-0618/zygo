# app/services/auth_service.py
# -*- coding: utf-8 -*-

from flask import current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from app import db
from app.models import User


def register_user(username, password):
    """创建新用户并存入数据库"""
    if User.query.filter_by(username=username).first():
        return None, "用户名已存在"

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user, "用户注册成功"


def verify_user(username, password):
    """验证用户名和密码"""
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user
    return None


def generate_auth_token(user_id, expires_in=864000):
    """为用户ID生成一个有时效性的认证Token"""
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps({'id': user_id})


def verify_auth_token(token):
    """验证Token并返回用户对象"""
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=3600 * 24 * 10)  # 设置一个比生成时更长的有效期用于验证
    except (SignatureExpired, BadTimeSignature):
        return None  # Token无效或已过期

    user = User.query.get(data['id'])
    return user