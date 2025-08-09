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
        self._app_instance = None  # 缓存应用实例
        self.connection_status: Dict[str, bool] = {}  # device_id -> connection_status
    
    def add_message_callback(self, callback: Callable):
        """添加消息回调函数，用于实时推送"""
        self.message_callbacks.append(callback)
    
    def remove_message_callback(self, callback: Callable):
        """移除消息回调函数"""
        if callback in self.message_callbacks:
            self.message_callbacks.remove(callback)

    def _get_app_context(self):
        """获取应用上下文"""
        if self._app_instance is None:
            from app import create_app
            self._app_instance = create_app('development')
        return self._app_instance.app_context()
    
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

        # 清理所有客户端连接
        with self.lock:
            for device_id in list(self.clients.keys()):
                try:
                    client = self.clients[device_id]
                    client.disconnect()
                    client.loop_stop()
                except Exception as e:
                    try:
                        with self._get_app_context():
                            current_app.logger.warning(f"停止监控时清理设备 {device_id} 失败: {str(e)}")
                    except:
                        print(f"停止监控时清理设备 {device_id} 失败: {str(e)}")

            self.clients.clear()
            self.device_configs.clear()

        try:
            with self._get_app_context():
                current_app.logger.info("MQTT监控服务已停止")
        except:
            print("MQTT监控服务已停止")
    
    def add_device_monitoring(self, device_id: str):
        """为指定设备添加MQTT监控"""
        try:
            with self._get_app_context():
                device = Device.query.filter_by(internal_device_id=device_id).first()
                if not device or not device.mqtt_monitoring_enabled:
                    print(f"设备 {device_id} 不存在或未启用MQTT监控")
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
                    'topics': device.mqtt_subscribe_topics or []
                }

                current_app.logger.info(f"开始为设备 {device_id} 添加MQTT监控: {config['host']}:{config['port']}")

            with self.lock:
                self.device_configs[device_id] = config
                self._connect_device(device_id, config)

            return True
        except Exception as e:
            print(f"添加设备 {device_id} MQTT监控失败: {str(e)}")
            return False
    
    def remove_device_monitoring(self, device_id: str):
        """移除指定设备的MQTT监控"""
        with self.lock:
            if device_id in self.clients:
                try:
                    client = self.clients[device_id]
                    client.disconnect()
                    client.loop_stop()
                    # 给一点时间让线程清理
                    time.sleep(0.1)
                except Exception as e:
                    try:
                        with self._get_app_context():
                            current_app.logger.warning(f"清理设备 {device_id} MQTT客户端时出错: {str(e)}")
                    except:
                        print(f"清理设备 {device_id} MQTT客户端时出错: {str(e)}")
                finally:
                    del self.clients[device_id]

            if device_id in self.device_configs:
                del self.device_configs[device_id]

            if device_id in self.connection_status:
                del self.connection_status[device_id]

    def is_device_connected(self, device_id: str) -> bool:
        """检查设备MQTT连接状态"""
        # 首先检查我们自己维护的连接状态
        if device_id in self.connection_status:
            status = self.connection_status[device_id]
            print(f"设备 {device_id} 连接状态(缓存): {status}")
            return status

        # 如果没有缓存状态，检查客户端是否存在
        if device_id not in self.clients:
            print(f"设备 {device_id} 不在客户端列表中")
            return False

        client = self.clients[device_id]
        try:
            # 检查paho-mqtt客户端的连接状态
            # 使用is_connected()方法或检查_state属性
            if hasattr(client, 'is_connected'):
                is_connected = client.is_connected()
            elif hasattr(client, '_state'):
                # 对于不同版本的paho-mqtt，连接状态常量可能不同
                # 通常连接状态为1表示已连接
                is_connected = client._state == 1
            else:
                # 如果都没有，假设未连接
                is_connected = False

            # 更新缓存状态
            self.connection_status[device_id] = is_connected
            print(f"设备 {device_id} 连接状态: {is_connected}, 客户端状态: {getattr(client, '_state', 'unknown')}")
            return is_connected
        except Exception as e:
            print(f"检查设备 {device_id} 连接状态时出错: {str(e)}")
            self.connection_status[device_id] = False
            return False
    
    def _connect_device(self, device_id: str, config: dict):
        """连接指定设备的MQTT broker"""
        try:
            # 如果已有连接，先断开
            if device_id in self.clients:
                try:
                    self.clients[device_id].disconnect()
                    self.clients[device_id].loop_stop()
                except:
                    pass
                del self.clients[device_id]

            # 创建MQTT客户端，使用MQTTv311协议版本以提高兼容性
            client = mqtt.Client(
                client_id=config['client_id'],
                protocol=mqtt.MQTTv311,
                clean_session=True
            )

            # 设置回调函数
            client.on_connect = lambda client, userdata, flags, rc: self._on_connect(device_id, client, userdata, flags, rc)
            client.on_message = lambda client, userdata, msg: self._on_message(device_id, client, userdata, msg)
            client.on_disconnect = lambda client, userdata, rc: self._on_disconnect(device_id, client, userdata, rc)
            client.on_log = lambda client, userdata, level, buf: self._on_log(device_id, level, buf)

            # 设置用户名和密码（只有在提供了用户名时才设置）
            if config.get('username'):
                password = config.get('password', '')  # 密码可以为空
                client.username_pw_set(config['username'], password)
                current_app.logger.info(f"设备 {device_id} 使用用户名认证: {config['username']}")
            else:
                current_app.logger.info(f"设备 {device_id} 使用匿名连接")

            # 存储客户端
            self.clients[device_id] = client

            # 连接到broker
            current_app.logger.info(f"正在连接设备 {device_id} 的MQTT broker: {config['host']}:{config['port']}")
            current_app.logger.info(f"设备 {device_id} 配置详情: 用户名={config.get('username', '无')}, 客户端ID={config['client_id']}, 主题={config.get('topics', [])}")

            # 使用异步连接以避免阻塞
            try:
                client.connect_async(config['host'], config['port'], 60)
                client.loop_start()
            except Exception as connect_error:
                current_app.logger.error(f"设备 {device_id} 连接启动失败: {str(connect_error)}")
                # 如果异步连接失败，尝试同步连接
                client.connect(config['host'], config['port'], 60)
                client.loop_start()

        except Exception as e:
            current_app.logger.error(f"连接设备 {device_id} 的MQTT broker失败: {str(e)}")
            # 清理失败的连接
            if device_id in self.clients:
                del self.clients[device_id]
    
    def _on_connect(self, device_id: str, client, userdata, flags, rc):
        """MQTT连接回调"""
        try:
            with self._get_app_context():
                if rc == 0:
                    current_app.logger.info(f"设备 {device_id} MQTT连接成功")
                    # 更新连接状态
                    self.connection_status[device_id] = True

                    # 订阅主题
                    config = self.device_configs.get(device_id, {})
                    topics = config.get('topics', [])
                    if topics:
                        for topic in topics:
                            if topic.strip():  # 确保主题不为空
                                client.subscribe(topic.strip())
                                current_app.logger.info(f"设备 {device_id} 订阅主题: {topic.strip()}")
                    else:
                        current_app.logger.info(f"设备 {device_id} 未配置订阅主题")
                else:
                    error_messages = {
                        1: "协议版本不正确",
                        2: "客户端标识符无效",
                        3: "服务器不可用",
                        4: "用户名或密码错误",
                        5: "未授权"
                    }
                    error_msg = error_messages.get(rc, f"未知错误码: {rc}")
                    current_app.logger.error(f"设备 {device_id} MQTT连接失败: {error_msg}")

                    # 连接失败时清理客户端和状态
                    self.connection_status[device_id] = False
                    if device_id in self.clients:
                        del self.clients[device_id]
        except Exception as e:
            print(f"MQTT连接回调处理错误: {str(e)}")  # 使用print避免循环依赖
    
    def _on_message(self, device_id: str, client, userdata, msg):
        """MQTT消息回调"""
        try:
            # 解码消息
            payload = msg.payload.decode('utf-8', errors='ignore')

            # 使用应用上下文存储到数据库
            with self._get_app_context():
                try:
                    mqtt_log = MqttLog(
                        device_id=device_id,
                        topic=msg.topic,
                        payload=payload,
                        direction='incoming',
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(mqtt_log)
                    db.session.commit()

                    current_app.logger.debug(f"设备 {device_id} 收到MQTT消息: {msg.topic} -> {payload}")
                except Exception as db_error:
                    current_app.logger.error(f"保存设备 {device_id} MQTT消息到数据库失败: {str(db_error)}")

            # 调用回调函数进行实时推送（不需要应用上下文）
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
                    print(f"MQTT消息回调执行失败: {str(e)}")  # 使用print避免应用上下文问题

        except Exception as e:
            print(f"处理设备 {device_id} MQTT消息失败: {str(e)}")  # 使用print避免应用上下文问题
    
    def _on_disconnect(self, device_id: str, client, userdata, rc):
        """MQTT断开连接回调"""
        try:
            # 更新连接状态
            self.connection_status[device_id] = False

            with self._get_app_context():
                if rc != 0:
                    current_app.logger.warning(f"设备 {device_id} MQTT意外断开连接，错误码: {rc}")
                    # 清理断开的客户端
                    if device_id in self.clients:
                        del self.clients[device_id]
                else:
                    current_app.logger.info(f"设备 {device_id} MQTT正常断开连接")
        except Exception as e:
            print(f"MQTT断开连接回调处理错误: {str(e)}")

    def _on_log(self, device_id: str, level, buf):
        """MQTT日志回调"""
        try:
            # 只记录错误和警告级别的日志，避免过多日志
            if level <= mqtt.MQTT_LOG_WARNING:
                with self._get_app_context():
                    current_app.logger.debug(f"设备 {device_id} MQTT日志: {buf}")
        except Exception as e:
            # 日志回调出错时使用print，避免无限循环
            if level <= mqtt.MQTT_LOG_WARNING:
                print(f"设备 {device_id} MQTT日志: {buf}")
    
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
