# app/models.py

import uuid
import json
from werkzeug.security import generate_password_hash, check_password_hash
from . import db


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # 用户的个人配置
    wifi_ssid = db.Column(db.String(64), nullable=True)
    wifi_password = db.Column(db.String(64), nullable=True)

    # 'User'和'Device'之间的一对多关系
    devices = db.relationship('Device', backref='owner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    # 使用UUID确保系统生成的ID全局唯一
    internal_device_id = db.Column(db.String(36), unique=True, nullable=False,
                                   default=lambda: str(uuid.uuid4()))
    nickname = db.Column(db.String(64), nullable=False)
    board_model = db.Column(db.String(64), nullable=False)

    # 云平台信息
    cloud_platform = db.Column(db.String(32), default='tuya')
    cloud_product_id = db.Column(db.String(64), nullable=True)
    cloud_device_id = db.Column(db.String(64), nullable=True)
    cloud_device_secret = db.Column(db.String(64), nullable=True)

    # 【核心修改】使用Text字段存储JSON字符串形式的外设列表
    # 我们使用一个"私有"的列名 _peripherals
    _peripherals = db.Column('peripherals', db.Text, nullable=True)

    # MQTT相关字段
    mqtt_broker_host = db.Column(db.String(255), nullable=True)
    mqtt_broker_port = db.Column(db.Integer, default=1883)
    mqtt_username = db.Column(db.String(64), nullable=True)
    mqtt_password = db.Column(db.String(64), nullable=True)
    mqtt_client_id = db.Column(db.String(64), nullable=True)
    _mqtt_subscribe_topics = db.Column('mqtt_subscribe_topics', db.Text, nullable=True)  # JSON数组
    mqtt_monitoring_enabled = db.Column(db.Boolean, default=False)

    # 指向'User'模型的外键
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @property
    def peripherals(self):
        """
        获取外设列表的属性。
        这个getter方法会自动将存储在数据库中的JSON字符串反序列化为Python列表。
        这使得在代码的其他部分可以像操作普通列表一样操作 device.peripherals。
        """
        if self._peripherals is None:
            return []
        try:
            return json.loads(self._peripherals)
        except (json.JSONDecodeError, TypeError):
            # 如果数据库中的数据格式不正确，返回一个空列表以避免程序崩溃
            return []

    @peripherals.setter
    def peripherals(self, value):
        """
        设置外设列表的属性。
        这个setter方法会自动将传入的Python列表或字典序列化为JSON字符串以便存入数据库。
        """
        if value is None:
            self._peripherals = None
        elif isinstance(value, (list, dict)):
            self._peripherals = json.dumps(value, ensure_ascii=False)
        else:
            # 如果传入了不支持的类型，则抛出异常
            raise ValueError('Peripherals must be a list or dictionary')

    @property
    def mqtt_subscribe_topics(self):
        """
        获取MQTT订阅主题列表的属性。
        这个getter方法会自动将存储在数据库中的JSON字符串反序列化为Python列表。
        """
        if self._mqtt_subscribe_topics is None:
            return []
        try:
            return json.loads(self._mqtt_subscribe_topics)
        except (json.JSONDecodeError, TypeError):
            # 如果数据库中的数据格式不正确，返回一个空列表以避免程序崩溃
            return []

    @mqtt_subscribe_topics.setter
    def mqtt_subscribe_topics(self, value):
        """
        设置MQTT订阅主题列表的属性。
        这个setter方法会自动将传入的Python列表序列化为JSON字符串以便存入数据库。
        """
        if value is None:
            self._mqtt_subscribe_topics = None
        elif isinstance(value, list):
            self._mqtt_subscribe_topics = json.dumps(value, ensure_ascii=False)
        else:
            # 如果传入了不支持的类型，则抛出异常
            raise ValueError('MQTT subscribe topics must be a list')


class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    # 使用Text字段存储完整的项目配置JSON字符串
    config_json = db.Column(db.Text, nullable=False)

    # 指向 User 模型的外键
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # 与User建立关系
    owner = db.relationship('User', backref=db.backref('projects', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'config_json': json.loads(self.config_json)  # 返回时反序列化
        }


class WorkflowState(db.Model):
    __tablename__ = 'workflow_states'
    # 使用工作流ID作为主键
    workflow_id = db.Column(db.String(36), primary_key=True)

    # 使用Text字段存储序列化后的整个工作流状态JSON
    state_json = db.Column(db.Text, nullable=False)

    # 记录最后更新时间，便于未来可能的清理
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    # 【核心新增】添加一个Text字段用于存储实时日志
    logs = db.Column(db.Text, default='')


class MqttLog(db.Model):
    __tablename__ = 'mqtt_logs'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.internal_device_id'), nullable=False)
    topic = db.Column(db.String(255), nullable=False)
    payload = db.Column(db.Text, nullable=True)
    direction = db.Column(db.String(10), nullable=False)  # 'incoming' or 'outgoing'
    timestamp = db.Column(db.DateTime, default=db.func.now())

    # 与Device建立关系
    device = db.relationship('Device', backref=db.backref('mqtt_logs', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'topic': self.topic,
            'payload': self.payload,
            'direction': self.direction,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }