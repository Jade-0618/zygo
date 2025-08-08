# python_bridge.py
import paho.mqtt.client as mqtt
from tuya_iot import TuyaOpenAPI, TuyaOpenMQ, TUYA_LOGGER
import json
import logging

# --- 1. 本地MQTT服务器配置 ---
LOCAL_MQTT_HOST = "192.168.104.148"
LOCAL_MQTT_PORT = 1883
DATA_TOPIC_FROM_ESP32 = "/data/esp32_device/report"
COMMAND_TOPIC_TO_ESP32 = "/cmd/esp32_device/set"

# --- 2. 涂鸦云平台配置 (已根据您的信息填写完毕) ---
TUYA_API_ENDPOINT = "https://openapi.tuyacn.com"
TUYA_ACCESS_ID = "kgiafmtndwhiakwc"  # 使用您的ProductID作为Access ID
TUYA_ACCESS_KEY = "EHbq0HPbg29Hmf0m"  # 使用您的DeviceSecret作为Access Key (注：此处用法特殊，匹配特定项目类型)
TUYA_DEVICE_ID = "26b23be8045c19bfd0yrth"  # 您的设备ID

# 启用详细日志，方便排查问题
# TUYA_LOGGER.setLevel(logging.DEBUG)

# --- 3. 初始化与连接 ---
openapi = TuyaOpenAPI(TUYA_API_ENDPOINT, TUYA_ACCESS_ID, TUYA_ACCESS_KEY)
openapi.connect()
openmq = TuyaOpenMQ(openapi)


# --- 4. 定义本地MQTT客户端的回调函数 ---
# 当从ESP32收到数据时触发
def on_local_message(client, userdata, msg):
    try:
        payload_str = msg.payload.decode('utf-8')
        print(f"[LOCAL] Received data from ESP32: {payload_str}")

        data = json.loads(payload_str)

        # 将数据格式化为涂鸦云需要的格式
        # 假设我们上报的是温度，涂鸦云上对应的标识符(code)是 "va_temperature"
        # 您需要根据您在涂鸦平台定义的功能点来修改这里的 "code"
        if "temperature" in data:
            # 涂鸦要求温度值为整数，所以如果是25.5度，需要乘以10上报255
            commands = {'commands': [{'code': 'va_temperature', 'value': int(data['temperature'] * 10)}]}

            print(f"[CLOUD] Forwarding data to Tuya Cloud: {commands}")
            openapi.post(f'/v1.0/devices/{TUYA_DEVICE_ID}/commands', commands)

    except Exception as e:
        print(f"Error processing message from ESP32: {e}")


# --- 5. 定义涂鸦云消息队列的回调函数 ---
# 当从涂鸦云收到指令时触发
def on_tuya_message(msg):
    try:
        print(f"[CLOUD] Received command from Tuya Cloud: {msg}")
        # 假设我们收到的指令是控制LED开关，涂鸦云上的标识符是 "switch_led"
        if msg.get('code') == 'switch_led':
            command_payload = {"led_on": msg.get('value')}

            print(f"[LOCAL] Forwarding command to ESP32: {command_payload}")
            local_client.publish(COMMAND_TOPIC_TO_ESP32, json.dumps(command_payload))

    except Exception as e:
        print(f"Error processing message from Tuya Cloud: {e}")


# --- 6. 主程序 ---
if __name__ == "__main__":
    # 设置并连接本地MQTT客户端
    local_client = mqtt.Client()
    local_client.on_message = on_local_message
    local_client.connect(LOCAL_MQTT_HOST, LOCAL_MQTT_PORT, 60)
    local_client.subscribe(DATA_TOPIC_FROM_ESP32)

    # 启动本地MQTT客户端的后台线程
    local_client.loop_start()
    print("[LOCAL] Connected to local MQTT Broker and subscribed to data topic.")

    # 启动涂鸦云消息队列
    openmq.start()
    openmq.add_message_listener(on_tuya_message)
    print("[CLOUD] Connected to Tuya Cloud and listening for commands.")

    print("\nBridge is running. Press Ctrl+C to exit.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        openmq.stop()
        local_client.loop_stop()
        print("\nBridge stopped.")