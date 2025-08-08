# app/api/mqtt_routes.py
# -*- coding: utf-8 -*-

import json
import time
from flask import Blueprint, request, jsonify, g, Response, stream_with_context
from app.services import mqtt_service
from app.models import Device, MqttLog
from .device_routes import token_required
from app import db
import paho.mqtt.client as mqtt

mqtt_blueprint = Blueprint('mqtt_api', __name__)


@mqtt_blueprint.route('/devices/<device_id>/logs', methods=['GET'])
@token_required
def get_device_mqtt_logs(device_id):
    """获取指定设备的MQTT日志"""
    # 验证设备是否属于当前用户
    device = Device.query.filter_by(
        internal_device_id=device_id, 
        user_id=g.current_user.id
    ).first_or_404()
    
    # 获取查询参数
    limit = min(int(request.args.get('limit', 100)), 1000)  # 最大1000条
    offset = int(request.args.get('offset', 0))
    topic_filter = request.args.get('topic')
    direction_filter = request.args.get('direction')  # incoming/outgoing    

    # 构建查询
    query = MqttLog.query.filter_by(device_id=device_id)

    if topic_filter:
        query = query.filter(MqttLog.topic.like(f'%{topic_filter}%'))        

    if direction_filter in ['incoming', 'outgoing']:
        query = query.filter_by(direction=direction_filter)

    # 执行查询
    logs = query.order_by(MqttLog.timestamp.desc())\
               .limit(limit)\
               .offset(offset)\
               .all()

    # 获取总数
    total_count = query.count()

    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total_count': total_count,
        'limit': limit,
        'offset': offset
    }), 200


@mqtt_blueprint.route('/devices/<device_id>/logs/stream', methods=['GET'])   
def stream_device_mqtt_logs(device_id):
    """为指定设备建立MQTT日志实时流"""
    # 手动验证token（因为EventSource不支持自定义headers）
    token = request.args.get('token')
    if not token:
        return Response('Missing token', status=401)

    # 验证token并获取用户
    from app.services import auth_service
    try:
        user = auth_service.verify_auth_token(token)
        if not user:
            return Response('Invalid token', status=401)
    except Exception:
        return Response('Invalid token', status=401)

    # 验证设备是否属于当前用户
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=user.id
    ).first_or_404()

    def generate_mqtt_logs():
        """生成MQTT日志流"""
        last_log_id = 0

        # 定义消息回调函数
        def mqtt_callback(log_data):
            nonlocal last_log_id
            if log_data['device_id'] == device_id:
                # 发送新的日志数据
                yield f"data: {json.dumps(log_data)}\n\n"

        # 注册回调函数
        mqtt_service.mqtt_monitor.add_message_callback(mqtt_callback)        

        try:
            # 发送初始的历史日志
            recent_logs = MqttLog.query.filter_by(device_id=device_id)\
                                     .order_by(MqttLog.timestamp.desc())\
                                     .limit(50)\
                                     .all()

            for log in reversed(recent_logs):  # 按时间正序发送
                yield f"data: {json.dumps(log.to_dict())}\n\n"
                last_log_id = log.id

            # 保持连接，等待新消息
            while True:
                # 检查是否有新的日志（防止回调函数失效的备用机制）
                new_logs = MqttLog.query.filter_by(device_id=device_id)\
                                       .filter(MqttLog.id > last_log_id)\
                                       .order_by(MqttLog.timestamp.asc())\
                                       .all()

                for log in new_logs:
                    yield f"data: {json.dumps(log.to_dict())}\n\n"
                    last_log_id = log.id

                time.sleep(1)  # 1秒检查一次

        except GeneratorExit:
            # 客户端断开连接时清理回调函数
            mqtt_service.mqtt_monitor.remove_message_callback(mqtt_callback) 
        except Exception as e:
            mqtt_service.mqtt_monitor.remove_message_callback(mqtt_callback) 
            yield f"data: {{\"error\": \"Stream error: {str(e)}\"}}\n\n"     

    return Response(
        stream_with_context(generate_mqtt_logs()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        }
    )


@mqtt_blueprint.route('/devices/<device_id>/publish', methods=['POST'])      
@token_required
def publish_mqtt_message(device_id):
    """向指定设备发布MQTT消息"""
    # 验证设备是否属于当前用户
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    data = request.get_json()
    if not data or not data.get('topic') or 'payload' not in data:
        return jsonify({'error': '缺少必要的参数：topic 和 payload'}), 400   

    topic = data['topic']
    payload = data['payload']
    qos = data.get('qos', 0)
    retain = data.get('retain', False)

    # 验证QoS值
    if qos not in [0, 1, 2]:
        return jsonify({'error': 'QoS值必须是0、1或2'}), 400

    # 发布消息
    success = mqtt_service.publish_mqtt_message(device_id, topic, str(payload), qos, retain)

    if success:
        return jsonify({'message': '消息发布成功'}), 200
    else:
        return jsonify({'error': '消息发布失败，请检查设备MQTT连接状态'}), 500


@mqtt_blueprint.route('/devices/<device_id>/mqtt/config', methods=['GET'])   
@token_required
def get_device_mqtt_config(device_id):
    """获取设备的MQTT配置"""
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    return jsonify({
        'mqtt_broker_host': device.mqtt_broker_host,
        'mqtt_broker_port': device.mqtt_broker_port,
        'mqtt_username': device.mqtt_username,
        'mqtt_client_id': device.mqtt_client_id,
        'mqtt_subscribe_topics': device.mqtt_subscribe_topics,
        'mqtt_monitoring_enabled': device.mqtt_monitoring_enabled
    }), 200


@mqtt_blueprint.route('/devices/<device_id>/mqtt/config', methods=['PUT'])   
@token_required
def update_device_mqtt_config(device_id):
    """更新设备的MQTT配置"""
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    data = request.get_json()
    if not data:
        return jsonify({'error': '请求体不能为空'}), 400

    # 更新MQTT配置
    if 'mqtt_broker_host' in data:
        device.mqtt_broker_host = data['mqtt_broker_host']
    if 'mqtt_broker_port' in data:
        device.mqtt_broker_port = data['mqtt_broker_port']
    if 'mqtt_username' in data:
        device.mqtt_username = data['mqtt_username']
    if 'mqtt_password' in data:
        device.mqtt_password = data['mqtt_password']
    if 'mqtt_client_id' in data:
        device.mqtt_client_id = data['mqtt_client_id']
    if 'mqtt_subscribe_topics' in data:
        device.mqtt_subscribe_topics = data['mqtt_subscribe_topics']
    if 'mqtt_monitoring_enabled' in data:
        old_enabled = device.mqtt_monitoring_enabled
        device.mqtt_monitoring_enabled = data['mqtt_monitoring_enabled']     

        # 如果监控状态发生变化，更新监控服务
        if old_enabled != device.mqtt_monitoring_enabled:
            if device.mqtt_monitoring_enabled:
                mqtt_service.mqtt_monitor.add_device_monitoring(device_id)   
            else:
                mqtt_service.mqtt_monitor.remove_device_monitoring(device_id)

    try:
        db.session.commit()
        return jsonify({'message': 'MQTT配置更新成功'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'更新失败: {str(e)}'}), 500


@mqtt_blueprint.route('/devices/<device_id>/mqtt/status', methods=['GET'])   
@token_required
def get_device_mqtt_status(device_id):
    """获取设备的MQTT连接状态"""
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    # 检查设备MQTT连接状态
    is_connected = mqtt_service.mqtt_monitor.is_device_connected(device_id)

    status = {
        'monitoring_enabled': device.mqtt_monitoring_enabled,
        'is_connected': is_connected,
        'broker_host': device.mqtt_broker_host,
        'broker_port': device.mqtt_broker_port,
        'subscribed_topics': device.mqtt_subscribe_topics
    }

    return jsonify(status), 200


@mqtt_blueprint.route('/devices/<device_id>/mqtt/test', methods=['POST'])
@token_required
def test_device_mqtt_connection(device_id):
    """测试设备的MQTT连接"""
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    data = request.get_json()

    try:
        # 创建临时客户端进行测试，使用更兼容的配置
        test_client = mqtt.Client(
            client_id=f"test_{device_id}_{int(time.time())}",
            protocol=mqtt.MQTTv311,
            clean_session=True
        )

        # 设置认证信息
        if data.get('mqtt_username'):
            password = data.get('mqtt_password', '')
            test_client.username_pw_set(data['mqtt_username'], password)

        # 设置连接结果标志
        connection_result = {'success': False, 'error': None, 'completed': False}

        def on_connect(client, userdata, flags, rc):
            connection_result['completed'] = True
            if rc == 0:
                connection_result['success'] = True
            else:
                error_messages = {
                    1: "协议版本不正确",
                    2: "客户端标识符无效",
                    3: "服务器不可用",
                    4: "用户名或密码错误",
                    5: "未授权"
                }
                connection_result['error'] = error_messages.get(rc, f"连接失败，错误码: {rc}")

        def on_disconnect(client, userdata, rc):
            if not connection_result['completed']:
                connection_result['completed'] = True
                connection_result['error'] = f"连接断开，错误码: {rc}"

        test_client.on_connect = on_connect
        test_client.on_disconnect = on_disconnect

        # 尝试连接
        test_client.connect(data['mqtt_broker_host'], int(data.get('mqtt_broker_port', 1883)), 10)
        test_client.loop_start()

        # 等待连接结果
        for _ in range(100):  # 最多等待10秒
            if connection_result['completed']:
                break
            time.sleep(0.1)

        # 清理测试连接
        try:
            test_client.disconnect()
            test_client.loop_stop()
        except:
            pass

        if connection_result['success']:
            return jsonify({'success': True, 'message': 'MQTT连接测试成功'}), 200
        else:
            error_msg = connection_result['error'] or '连接超时，请检查服务器是否运行'
            return jsonify({'success': False, 'error': error_msg}), 400

    except Exception as e:
        error_msg = str(e)
        host = data["mqtt_broker_host"]

        # 检查是否包含协议前缀
        if any(prefix in host.lower() for prefix in ['mqtt://', 'mqtts://', 'tcp://', 'ssl://']):
            error_msg = f'主机名不应包含协议前缀！\n当前输入: "{host}"\n请只输入主机名，如: "localhost" 或 "192.168.1.100"'
        elif 'getaddrinfo failed' in error_msg:
            error_msg = f'无法解析主机名 "{host}"，请检查：\n1. 主机名是否正确（如: localhost, 127.0.0.1）\n2. 不要包含 mqtt:// 等协议前缀\n3. DNS设置是否正确'
        elif 'Connection refused' in error_msg:
            error_msg = f'连接被拒绝，请检查：\n1. MQTT服务器是否运行\n2. 端口 {data.get("mqtt_broker_port", 1883)} 是否正确\n3. 防火墙设置'
        elif 'timeout' in error_msg.lower():
            error_msg = f'连接超时，请检查：\n1. 主机名 "{host}" 是否可达\n2. 网络连接是否正常\n3. 防火墙是否阻止连接'

        return jsonify({'success': False, 'error': error_msg}), 400


@mqtt_blueprint.route('/devices/<device_id>/mqtt/topics', methods=['GET'])
@token_required
def get_device_mqtt_topics(device_id):
    """获取设备的MQTT主题统计"""
    device = Device.query.filter_by(
        internal_device_id=device_id,
        user_id=g.current_user.id
    ).first_or_404()

    # 获取最近的主题统计
    topics_stats = db.session.query(
        MqttLog.topic,
        db.func.count(MqttLog.id).label('message_count'),
        db.func.max(MqttLog.timestamp).label('last_message')
    ).filter_by(device_id=device_id)\
     .group_by(MqttLog.topic)\
     .order_by(db.func.max(MqttLog.timestamp).desc())\
     .limit(50)\
     .all()

    topics = []
    for topic, count, last_message in topics_stats:
        topics.append({
            'topic': topic,
            'message_count': count,
            'last_message': last_message.isoformat() if last_message else None
        })

    return jsonify({'topics': topics}), 200
