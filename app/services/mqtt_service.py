# app/services/mqtt_service.py
# -*- coding: utf-8 -*-

import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
import paho.mqtt.client as mqtt
from flask import current_app
from app import db
from app.models import Device, MqttLog


class MqttMonitorService:
    """MQTT监控服务，用于监听设备的MQTT消息并存储到数据库"""
    
    def __init__(self):
        self.clients: Dict[str, mqtt.Client] = {}  # device_id -> mqtt_client
        self.device_configs: Dict[str, dict] = {}  # device_id -> config
        self.message_callbacks: List[Callable] = []  # 消息回调函数列表
        self.running = False
        self.lock = threading.Lock()
    
    def add_message_callback(self, callback: Callable):
        """添加消息回调函数，用于实时推送"""
        self.message_callbacks.append(callback)
    
    def remove_message_callback(self, callback: Callable):
        """移除消息回调函数"""
        if callback in self.message_callbacks:
            self.message_callbacks.remove(callback)

    def start_monitoring(self):
        """启动MQTT监控服务"""
        if self.running:
            return

        self.running = True
        # 在后台线程中运行监控
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        current_app.logger.info("MQTT监控服务已启动")

    def stop_monitoring(self):
        """停止MQTT监控服务"""
        self.running = False
        with self.lock:
            for client in self.clients.values():
                try:
                    client.disconnect()
                except:
                    pass
            self.clients.clear()
            self.device_configs.clear()
        current_app.logger.info("MQTT监控服务已停止")

    def add_device_monitoring(self, device_id: str):
        """为指定设备添加MQTT监控"""
        with current_app.app_context():
            device = Device.query.filter_by(internal_device_id=device_id).first()
            if not device or not device.mqtt_monitoring_enabled:
                return False

            if not device.mqtt_broker_host:
                current_app.logger.warning(f"设备 {device_id} 未配置MQTT broker")
                return False

            config = {
                'host': device.mqtt_broker_host,
                'port': device.mqtt_broker_port or 1883,
                'username': device.mqtt_username,
                'password': device.mqtt_password,
                'client_id': device.mqtt_client_id or f"monitor_{device_id}",
                'topics': device.subscribe_topics or []
            }

            with self.lock:
                self.device_configs[device_id] = config
                self._connect_device(device_id, config)

            return True

    def remove_device_monitoring(self, device_id: str):
        """移除指定设备的MQTT监控"""
        with self.lock:
            if device_id in self.clients:
                try:
                    self.clients[device_id].disconnect()
                except:
                    pass
                del self.clients[device_id]

            if device_id in self.device_configs:
                del self.device_configs[device_id]

    def _connect_device(self, device_id: str, config: dict):
        """连接指定设备的MQTT broker"""
        try:
            client = mqtt.Client(client_id=config['client_id'])

            # 设置回调函数
            client.on_connect = lambda client, userdata, flags, rc: self._on_connect(device_id, client, userdata, flags, rc)
            client.on_message = lambda client, userdata, msg: self._on_message(device_id, client, userdata, msg)
            client.on_disconnect = lambda client, userdata, rc: self._on_disconnect(device_id, client, userdata, rc)

            # 设置用户名和密码
            if config.get('username') and config.get('password'):
                client.username_pw_set(config['username'], config['password'])

            # 连接到broker
            client.connect(config['host'], config['port'], 60)
            client.loop_start()

            self.clients[device_id] = client
            current_app.logger.info(f"正在连接设备 {device_id} 的MQTT broker: {config['host']}:{config['port']}")

        except Exception as e:
            current_app.logger.error(f"连接设备 {device_id} 的MQTT broker失败: {str(e)}")

    def _on_connect(self, device_id: str, client, userdata, flags, rc):      
        """MQTT连接回调"""
        if rc == 0:
            current_app.logger.info(f"设备 {device_id} MQTT连接成功")        
            # 订阅主题
            config = self.device_configs.get(device_id, {})
            topics = config.get('topics', [])
            for topic in topics:
                client.subscribe(topic)
                current_app.logger.info(f"设备 {device_id} 订阅主题: {topic}")
        else:
            current_app.logger.error(f"设备 {device_id} MQTT连接失败，错误码: {rc}")

    def _on_message(self, device_id: str, client, userdata, msg):
        """MQTT消息回调"""
        try:
            # 解码消息
            payload = msg.payload.decode('utf-8', errors='ignore')

            # 存储到数据库
            with current_app.app_context():
                mqtt_log = MqttLog(
                    device_id=device_id,
                    topic=msg.topic,
                    payload=payload,
                    qos=msg.qos,
                    retain=msg.retain,
                    direction='incoming',
                    timestamp=datetime.utcnow()
                )
                db.session.add(mqtt_log)
                db.session.commit()

            # 调用回调函数进行实时推送
            log_data = {
                'device_id': device_id,
                'topic': msg.topic,
                'payload': payload,
                'qos': msg.qos,
                'retain': msg.retain,
                'direction': 'incoming',
                'timestamp': datetime.utcnow().isoformat()
            }

            for callback in self.message_callbacks:
                try:
                    callback(log_data)
                except Exception as e:
                    current_app.logger.error(f"MQTT消息回调执行失败: {str(e)}")

            current_app.logger.debug(f"设备 {device_id} 收到MQTT消息: {msg.topic} -> {payload}")

        except Exception as e:
            current_app.logger.error(f"处理设备 {device_id} MQTT消息失败: {str(e)}")

    def _on_disconnect(self, device_id: str, client, userdata, rc):
        """MQTT断开连接回调"""
        current_app.logger.warning(f"设备 {device_id} MQTT连接断开，错误码: {rc}")

    def _monitor_loop(self):
        """监控循环，定期检查设备配置变化"""
        from flask import current_app

        while self.running:
            try:
                # 导入Flask应用实例
                from app import create_app
                app = create_app('development')

                with app.app_context():
                    try:
                        # 获取所有启用MQTT监控的设备
                        devices = Device.query.filter_by(mqtt_monitoring_enabled=True).all()

                        current_device_ids = set(self.device_configs.keys()) 
                        active_device_ids = set(device.internal_device_id for device in devices)

                        # 添加新设备
                        for device_id in active_device_ids - current_device_ids:
                            self.add_device_monitoring(device_id)

                        # 移除不再监控的设备
                        for device_id in current_device_ids - active_device_ids:
                            self.remove_device_monitoring(device_id)
                    except Exception as db_error:
                        # 如果数据库表不存在或其他数据库错误，跳过这次检查   
                        if "no such table" in str(db_error).lower():
                            pass  # 数据库表还未创建，跳过
                        else:
                            print(f"MQTT监控数据库查询错误: {str(db_error)}")

            except Exception as e:
                print(f"MQTT监控循环出错: {str(e)}")

            time.sleep(30)  # 每30秒检查一次


# 全局MQTT监控服务实例
mqtt_monitor = MqttMonitorService()


def get_device_mqtt_logs(device_id: str, limit: int = 100, offset: int = 0) -> List[dict]:
    """获取指定设备的MQTT日志"""
    logs = MqttLog.query.filter_by(device_id=device_id)\
                       .order_by(MqttLog.timestamp.desc())\
                       .limit(limit)\
                       .offset(offset)\
                       .all()
    return [log.to_dict() for log in logs]


def publish_mqtt_message(device_id: str, topic: str, payload: str, qos: int = 0, retain: bool = False) -> bool:
    """向指定设备发布MQTT消息"""
    try:
        client = mqtt_monitor.clients.get(device_id)
        if not client:
            return False

        # 发布消息
        result = client.publish(topic, payload, qos, retain)

        # 记录发送的消息
        with current_app.app_context():
            mqtt_log = MqttLog(
                device_id=device_id,
                topic=topic,
                payload=payload,
                qos=qos,
                retain=retain,
                direction='outgoing',
                timestamp=datetime.utcnow()
            )
            db.session.add(mqtt_log)
            db.session.commit()

        return result.rc == mqtt.MQTT_ERR_SUCCESS

    except Exception as e:
        current_app.logger.error(f"发布MQTT消息失败: {str(e)}")
        return False
