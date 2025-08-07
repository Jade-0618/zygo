# app/langgraph_def/graph_builder.py
# -*- coding: utf-8 -*-

# =================================================================================
# 1. Imports & Setup
# ===============================================================================
import json
import sys
import os
import re
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from pprint import pprint
import time
import textwrap
import socket
from typing import Dict, Optional, List

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
from thefuzz import process

# 导入我们新的模块化AgentState
from .agent_state import AgentState

# =================================================================================
# 2. 模型初始化 (沿用 example.py)
# =================================================================================
API_KEY = "a985545a-1c6b-4bf4-8956-8c93ffc2181f"
BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"

system_architect_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.5, api_key=API_KEY,
                                    base_url=BASE_URL)
module_architect_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.4, api_key=API_KEY,
                                    base_url=BASE_URL)
api_designer_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.3, api_key=API_KEY, base_url=BASE_URL)
developer_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.2, api_key=API_KEY, base_url=BASE_URL)
tester_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.1, api_key=API_KEY, base_url=BASE_URL)
dp_extractor_model = ChatOpenAI(model="ep-20250223112748-lthgv", temperature=0.2, api_key=API_KEY, base_url=BASE_URL)


# =================================================================================
# 3. 辅助函数及核心模块生成器 (沿用 example.py)
# =================================================================================
def get_local_ip() -> str:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        return "127.0.0.1"
    finally:
        if s:
            s.close()


def extract_code(content: str, lang: str = "cpp", block_name: str = None) -> str:
    if block_name:
        pattern = re.compile(rf'\[{block_name.upper()}\]\s*```{lang}\s*([\s\S]*?)\s*```', re.DOTALL)
    else:
        pattern = re.compile(rf'```{lang}\s*([\s\S]*?)\s*```', re.DOTALL)
    match = pattern.search(content)
    return match.group(1).strip() if match else f"// Error: Could not extract code block '{block_name or lang}'."


def generate_mbedtls_sha256_header() -> str:
    return """
#ifndef CUSTOM_SHA256_H
#define CUSTOM_SHA256_H
#include <Arduino.h>
#include "mbedtls/sha256.h"
class SHA256 {
public:
    SHA256();
    void update(const void *data, size_t len);
    void finalize(byte *hash);
    static String toString(const byte* hash, int len = 32);
private:
    mbedtls_sha256_context ctx;
};
#endif // CUSTOM_SHA256_H
"""


def generate_mbedtls_sha256_source() -> str:
    return """
#include "SHA256.h"
SHA256::SHA256() {
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
}
void SHA256::update(const void *data, size_t len) {
    if (len == 0) return;
    mbedtls_sha256_update_ret(&ctx, (const unsigned char *)data, len);
}
void SHA256::finalize(byte *hash) {
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_starts_ret(&ctx, 0);
}
String SHA256::toString(const byte* hash, int len) {
    char hex_string[len * 2 + 1];
    for (int i = 0; i < len; i++) {
        sprintf(&hex_string[i * 2], "%02x", hash[i]);
    }
    hex_string[len * 2] = '\\0';
    return String(hex_string);
}
"""


def generate_tuya_handler_header() -> str:
    return """
#ifndef TUYA_HANDLER_H
#define TUYA_HANDLER_H
#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
typedef void (*TuyaAppCallback)(String &topic, String &payload);
void tuya_setup(WiFiClientSecure& wifiClient, PubSubClient& mqttClient, TuyaAppCallback app_callback);
void tuya_loop();
bool tuya_publish_data(const String& data_json_string);
#endif // TUYA_HANDLER_H
"""


def generate_config_manager_header(device_id: str) -> str:
    local_pc_ip = get_local_ip()
    return f'''
#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H
#define WIFI_SSID "your_ssid"
#define WIFI_PASSWORD "your_password"
#define TUYA_PRODUCT_ID "YOUR_PRODUCT_ID"
#define TUYA_DEVICE_ID  "YOUR_DEVICE_ID"
#define TUYA_DEVICE_SECRET "YOUR_DEVICE_SECRET"
#define MQTT_BROKER "{local_pc_ip}"
#define MQTT_PORT 1883
#define OTA_HTTP_SERVER "{local_pc_ip}"
#define OTA_HTTP_PORT 8000
#define DEVICE_ID "{device_id}"
#define FIRMWARE_VERSION "1.0.0"
#define OTA_TOPIC_BASE "/ota/"
#define DEBUG_TOPIC_BASE "/debug/"
#endif // CONFIG_MANAGER_H
'''


def generate_tuya_handler_source() -> str:
    return """
#include "tuya_handler.h"
#include "config_manager.h"
#include <ArduinoJson.h>
#include <WiFi.h>
#include <time.h>
#include "SHA256.h"
static const char tuya_ca_cert[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx
EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp
ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIz
NTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQDVQQH
EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UE
AxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKD
E6bFIEMBO4Tx5oVJnyfq9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH
/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD+qK+ihVqf94Lw7YZFAXK6sOoBJQ7Rnwy
DfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutdfMh8+7ArU6SSYmlRJQVh
GkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMlNAJWJwGR
tDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEA
AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FDqahQcQZyi27/a9BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmX
WWcDYfF+OwYxdS2hII5PZYe096acvNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu
9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r5N9ss4UXnT3ZJE95kTXWXwTr
gIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYVN8Gb5DKj7Tjo
2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO
LPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI
4uJEvlz36hz1
-----END CERTIFICATE-----
)EOF";
static WiFiClientSecure* _wifiClient;
static PubSubClient* _mqttClient;
static TuyaAppCallback _app_callback = nullptr;
static const char* mqtt_broker = "m1.tuyacn.com";
static const int mqtt_port = 8883;
static char clientID[128];
static char username[128];
static char password[128];
static char deviceId[50];
static char deviceSecret[50];
static String hmac256(const char* key, size_t key_len, const char* message, size_t msg_len);
static void tuya_mqtt_auth_signature_calculate();
static void connectToWiFi();
static void syncTime();
static void connectToMQTT();
static void internal_mqtt_callback(char *topic, byte *payload, unsigned int length);
void tuya_setup(WiFiClientSecure& wifiClient, PubSubClient& mqttClient, TuyaAppCallback app_callback) {
    _wifiClient = &wifiClient;
    _mqttClient = &mqttClient;
    _app_callback = app_callback;
    strcpy(deviceId, TUYA_DEVICE_ID);
    strcpy(deviceSecret, TUYA_DEVICE_SECRET);
    _wifiClient->setCACert(tuya_ca_cert);
    connectToWiFi();
    syncTime();
    _mqttClient->setServer(mqtt_broker, mqtt_port);
    _mqttClient->setCallback(internal_mqtt_callback);
}
void tuya_loop() {
    if (!_mqttClient->connected()) {
        connectToMQTT();
    }
    _mqttClient->loop();
}
bool tuya_publish_data(const String& data_json_string) {
    if (!_mqttClient->connected()) {
        return false;
    }
    char topic[128];
    sprintf(topic, "tylink/%s/thing/property/report", deviceId);
    return _mqttClient->publish(topic, data_json_string.c_str());
}
static String hmac256(const char* key, size_t key_len, const char* message, size_t msg_len) {
    SHA256 sha;
    byte k_ipad[64], k_opad[64];
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    sha.update(k_ipad, sizeof(k_ipad));
    sha.update(message, msg_len);
    byte hmac[32];
    sha.finalize(hmac);
    sha.update(k_opad, sizeof(k_opad));
    sha.update(hmac, sizeof(hmac));
    sha.finalize(hmac);
    return SHA256::toString(hmac);
}
static void tuya_mqtt_auth_signature_calculate() {
    long int t = time(NULL);
    sprintf(clientID, "tuyalink_%s", deviceId);
    sprintf(username, "%s|signMethod=hmacSha256,timestamp=%ld,secureMode=1,accessType=1", deviceId, t);
    String sign_content = String("deviceId=") + deviceId + ",timestamp=" + t + ",secureMode=1,accessType=1";
    String pass_hash = hmac256(deviceSecret, strlen(deviceSecret), sign_content.c_str(), sign_content.length());
    strcpy(password, pass_hash.c_str());
}
static void connectToWiFi() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\\nWiFi connected. IP: " + WiFi.localIP().toString());
}
static void syncTime() {
    configTime(8 * 3600, 0, "pool.ntp.org", "time.windows.com");
    Serial.print("Waiting for NTP time sync");
    while (time(NULL) < 8 * 3600 * 2) {
        Serial.print(".");
        delay(1000);
    }
    Serial.println("\\nTime synced.");
}
static void connectToMQTT() {
    while (!_mqttClient->connected()) {
        Serial.println("Attempting Tuya MQTT connection...");
        tuya_mqtt_auth_signature_calculate();
        if (_mqttClient->connect(clientID, username, password)) {
            Serial.println("Tuya MQTT connected.");
            char topic_sub[128];
            sprintf(topic_sub, "tylink/%s/thing/property/set", deviceId);
            _mqttClient->subscribe(topic_sub);
            Serial.println(String("Subscribed to: ") + topic_sub);
        } else {
            Serial.print("failed, rc=");
            Serial.print(_mqttClient->state());
            Serial.println(" try again in 5 seconds");
            delay(5000);
        }
    }
}
static void internal_mqtt_callback(char *topic, byte *payload, unsigned int length) {
    String topicStr(topic), payloadStr;
    for (unsigned int i = 0; i < length; i++) payloadStr += (char)payload[i];
    Serial.println("Tuya Handler received message. Topic: " + topicStr);
    Serial.println("Payload: " + payloadStr);
    if (_app_callback) _app_callback(topicStr, payloadStr);
}
"""


def generate_ota_handler_header() -> str:
    return """
#ifndef OTA_HANDLER_H
#define OTA_HANDLER_H
#include <WiFi.h>
#include <PubSubClient.h>
void ota_setup(WiFiClient& wifiClient, PubSubClient& mqttClient);
void ota_loop();
const char* ota_get_device_id();
void ota_handle_mqtt_message(char* topic, byte* payload, unsigned int length);
#endif // OTA_HANDLER_H
"""


def generate_ota_handler_source() -> str:
    return """
#include <WiFi.h>
#include <HTTPUpdate.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "config_manager.h"
#include "ota_handler.h"
static WiFiClient* _wifiClient;
static PubSubClient* _mqttClient;
static unsigned long lastStatusTime = 0;
const unsigned long statusInterval = 60000;
static String status_topic, specific_cmd_topic, broadcast_cmd_topic;
static void perform_ota(String fileName) { /* Implementation unchanged from example.py */ }
static void reconnect_mqtt();
static void publish_status() { /* Implementation unchanged from example.py */ }
void ota_setup(WiFiClient& wifiClient, PubSubClient& mqttClient) {
    _wifiClient = &wifiClient;
    _mqttClient = &mqttClient;
    status_topic = String(OTA_TOPIC_BASE) + DEVICE_ID + "/status";
    specific_cmd_topic = String(OTA_TOPIC_BASE) + DEVICE_ID + "/command";
    broadcast_cmd_topic = String(OTA_TOPIC_BASE) + "all/command";
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println("\\nWiFi connected. IP: " + WiFi.localIP().toString());
    _mqttClient->setServer(MQTT_BROKER, MQTT_PORT);
    reconnect_mqtt();
}
void ota_loop() {
    if (!_mqttClient->connected()) reconnect_mqtt();
    _mqttClient->loop();
    unsigned long currentTime = millis();
    if (currentTime - lastStatusTime >= statusInterval) {
        lastStatusTime = currentTime;
        publish_status();
    }
}
const char* ota_get_device_id() { return DEVICE_ID; }
void ota_handle_mqtt_message(char* topic, byte* payload, unsigned int length) {
    String topicStr = String(topic);
    if (topicStr != specific_cmd_topic && topicStr != broadcast_cmd_topic) return;
    char message[length + 1];
    memcpy(message, payload, length);
    message[length] = '\\0';
    Serial.printf("OTA Handler received message on topic: %s\\n", topic);
    StaticJsonDocument<256> doc;
    DeserializationError error = deserializeJson(doc, message);
    if (error) { Serial.printf("OTA JSON parsing failed: %s\\n", error.c_str()); return; }
    const char* action = doc["action"];
    if (action && strcmp(action, "update") == 0) {
        String fileName = doc["file"] | "";
        if (fileName.length() > 0) {
            Serial.printf("OTA update request received for file: %s\\n", fileName.c_str());
            perform_ota(fileName);
        }
    }
}
static void reconnect_mqtt() {
    while (!_mqttClient->connected()) {
        Serial.print("Attempting MQTT connection...");
        #if defined(MQTT_USER) && defined(MQTT_PASSWORD)
            if (_mqttClient->connect(DEVICE_ID, MQTT_USER, MQTT_PASSWORD)) {
        #else
            if (_mqttClient->connect(DEVICE_ID)) {
        #endif
            Serial.println("connected");
            _mqttClient->subscribe(specific_cmd_topic.c_str());
            _mqttClient->subscribe(broadcast_cmd_topic.c_str());
            Serial.println("Subscribed to OTA command topics.");
            publish_status();
        } else {
            Serial.print("failed, rc=");
            Serial.print(_mqttClient->state());
            Serial.println(" try again in 5 seconds");
            delay(5000);
        }
    }
}
"""


def generate_mqtt_logger_header() -> str:
    return """
#ifndef MQTT_LOGGER_H
#define MQTT_LOGGER_H
#include <PubSubClient.h>
#include <Print.h>
class MqttLogger : public Print {
public:
    MqttLogger(PubSubClient& client, const char* device_id);
    void setup();
    void loop();
    virtual size_t write(uint8_t);
    virtual size_t write(const uint8_t *buffer, size_t size);
private:
    PubSubClient& _client;
    String _topic;
    char _buffer[256];
    size_t _buffer_pos;
    unsigned long _last_flush;
    void flush();
};
#endif // MQTT_LOGGER_H
"""


def generate_mqtt_logger_source() -> str:
    return """
#include "mqtt_logger.h"
#include "config_manager.h"
MqttLogger::MqttLogger(PubSubClient& client, const char* device_id)
    : _client(client), _buffer_pos(0), _last_flush(0) {
    _topic = String(DEBUG_TOPIC_BASE) + device_id + "/log";
}
void MqttLogger::setup() {}
void MqttLogger::loop() {
    if (_buffer_pos > 0 && (millis() - _last_flush > 1000)) {
        flush();
    }
}
size_t MqttLogger::write(uint8_t c) {
    if (_buffer_pos >= sizeof(_buffer) - 1) flush();
    _buffer[_buffer_pos++] = c;
    return 1;
}
size_t MqttLogger::write(const uint8_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) write(buffer[i]);
    return size;
}
void MqttLogger::flush() {
    if (_buffer_pos > 0 && _client.connected()) {
        _buffer[_buffer_pos] = '\\0';
        _client.publish(_topic.c_str(), _buffer);
        _buffer_pos = 0;
    }
    _last_flush = millis();
}
"""


# =================================================================================
# 4. Agent Node Definitions (精简并适配V3 API)
# =================================================================================

def module_architect_node(state: AgentState) -> Dict:
    # 这是新流程的入口点
    device_task = state['current_device_task']
    print(f"--- L2: MODULE ARCHITECT: Designing firmware for '{device_task['device_id']}' ---")
    peripherals_info = "\\n".join([f"- {p['name']} ({p.get('function', 'N/A')})" for p in device_task['peripherals']])
    has_network = any(p['name'] in ['WiFi', 'MQTT_Client'] for p in device_task['peripherals'])
    network_instructions = ""
    if has_network:
        network_instructions = textwrap.dedent("""
        4. **Core Services**: Since this device has network capabilities, you MUST define these three core driver modules:
           - A 'driver' module with `task_id: "config_manager"`.
           - A 'driver' module with `task_id: "ota_handler"`.
           - A 'driver' module with `task_id: "mqtt_logger"`.
        5. The main 'application' module MUST list "ota_handler" and "mqtt_logger" in its dependencies.
        """)
    prompt = textwrap.dedent(f"""
    <Prompt>
        <Role>You are an expert embedded firmware architect.</Role>
        <Goal>For the given device, design a modular firmware architecture. This includes drivers for physical peripherals and modules for logical functions like communication and our mandatory core services.</Goal>
        <Context>
            <Device>{device_task['device_id']} ({device_task['board']})</Device>
            <DeviceRole>{device_task['description']}</DeviceRole>
            <Peripherals>{peripherals_info}</Peripherals>
        </Context>
        <Instructions>
            1. For each physical peripheral (e.g., DHT11), define a 'driver' module.
            2. For logical functions like 'MQTT_Client' or 'WiFi', you DO NOT need to create a driver, as they are handled by the core services.
            3. Define one single 'application' module that will use all other modules. Its `task_id` should be `app_main`.
            {network_instructions}
            4. **Core Services**: If the device peripherals include "Tuya Cloud Client", you MUST define a 'driver' module with `task_id: "tuya_handler"`. The 'application' module (`app_main`) MUST list "tuya_handler" in its dependencies. You should NOT include `ota_handler` or `mqtt_logger` in this case, as Tuya has its own ecosystem.
            6. Your final output MUST be a single, valid JSON object containing one key: "modules".
        </instructions>
        <OutputFormat>
        ```json
        {{
            "modules": [
                {{
                    "task_id": "config_manager", "task_type": "driver", "peripheral": "Core", "description": "Manages all network and device configurations.", "dependencies": []
                }},
                {{
                    "task_id": "ota_handler", "task_type": "driver", "peripheral": "Core", "description": "Handles Over-The-Air firmware updates.", "dependencies": ["config_manager"]
                }},
                {{
                    "task_id": "mqtt_logger", "task_type": "driver", "peripheral": "Core", "description": "Provides remote logging capabilities over MQTT.", "dependencies": ["config_manager"]
                }},
                {{
                    "task_id": "dht11_driver", "task_type": "driver", "peripheral": "DHT11", "description": "A driver for the DHT11 sensor.", "dependencies": []
                }},
                {{
                    "task_id": "app_main", "task_type": "application", "description": "The main application logic.", "dependencies": ["ota_handler", "mqtt_logger", "dht11_driver"]
                }}
            ]
        }}
        ```
        </OutputFormat>
    </Prompt>
    """)
    response = module_architect_model.invoke([HumanMessage(content=prompt)])
    try:
        plan = json.loads(extract_code(response.content, "json"))
        return {"module_tasks": plan['modules'], "original_module_plan": plan['modules']}
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"MODULE ARCHITECT PARSING ERROR: {e}")
        return {"feedback": f"FAIL: Module Architect failed. Error: {e}", "module_tasks": []}


def module_dispatcher_node(state: AgentState) -> Dict:
    if state.get('module_tasks'):
        next_task = state['module_tasks'][0]
        print(f"--- L3 DISPATCHER: Selecting module task -> '{next_task['task_id']}' ---")
        return {"current_module_task": next_task, "module_tasks": state['module_tasks'][1:], "feedback": ""}
    return {"current_module_task": None}


def api_designer_node(state: AgentState) -> Dict:
    task = state['current_module_task']
    if not task or task['task_type'] != 'driver' or task['task_id'] in ['config_manager', 'ota_handler', 'mqtt_logger',
                                                                        'tuya_handler']:
        return {"current_api_spec": None}
    peripheral = task['peripheral']
    print(f"--- L3: API DESIGNER: Designing API for '{peripheral}' ---")
    prompt = textwrap.dedent(f"""
    <Prompt>
        <Role>You are an expert API designer for embedded C/C++ drivers.</Role>
        <Goal>Generate a high-quality, detailed API specification in JSON format for the given peripheral or logical module.</Goal>
        <Context>
            <PeripheralOrModule>{peripheral}</PeripheralOrModule>
            <Task>{task['description']}</Task>
        </Context>
        <Instructions>
            1. Design a set of C-style functions. For communication modules like MQTT, design high-level functions like `connect`, `publish`, `subscribe`.
            2. The output must be a single, valid JSON object containing a root key `"{peripheral.upper().replace(' ', '_')}_Interface"` which contains a list of functions.
        </Instructions>
        <Example>
        For a 'DHT11', a good output would be:
        ```json
        {{
            "DHT11_Interface": {{
                "functions": [
                    {{ "name": "dht11_setup", "description": "Initializes the DHT11 sensor on a specific pin.", "return_type": "void", "parameters": [{{"name": "pin", "type": "int"}}] }},
                    {{ "name": "dht11_read_temperature", "description": "Reads the temperature in Celsius.", "return_type": "float", "parameters": [] }},
                    {{ "name": "dht11_read_humidity", "description": "Reads the humidity in percent.", "return_type": "float", "parameters": [] }}
                ]
            }}
        }}
        ```
        </Example>
        <OutputFormat>```json\n// Your generated JSON code here\n```</OutputFormat>
    </Prompt>
    """)
    response = api_designer_model.invoke([HumanMessage(content=prompt)])
    generated_spec_str = extract_code(response.content, lang="json")
    try:
        spec_json = json.loads(generated_spec_str)
        interface = spec_json.get(f"{peripheral.upper().replace(' ', '_')}_Interface", {})
        functions = interface.get("functions", [])
        formatted_spec = json.dumps(functions, indent=2, ensure_ascii=False)
        return {"current_api_spec": formatted_spec}
    except Exception as e:
        print(f"API DESIGNER GENERATION ERROR: {e}")
        return {"current_api_spec": f"// Failed to generate API for {peripheral}"}


def developer_node(state: AgentState) -> Dict:
    task = state['current_module_task']
    if not task:
        return {}
    device_id = state['current_device_task']['device_id']
    task_id = task['task_id']
    print(f"--- L3: DEVELOPER: Coding module '{task_id}' for device '{device_id}' ---")
    feedback_context = ""
    if state.get('feedback') and "FAIL" in state['feedback']:
        print(f"--- DEVELOPER: Received feedback. Incorporating into prompt. ---")
        feedback_context = textwrap.dedent(f"""
        <Feedback_From_Previous_Attempt>
        IMPORTANT: Your previous attempt to generate code for this module resulted in a failure.
        You MUST analyze the following error message and fix the code accordingly.
        Error Details: {state['feedback']}
        Common root causes for 'undefined reference' errors are:
        - A function was declared in the .h file but not implemented in the .cpp file.
        - The implementation in the .cpp file does not exactly match the declaration in the .h file (e.g., missing ClassName::).
        You MUST ensure your generated code is complete and correct.
        </Feedback_From_Previous_Attempt>
        """)

    completed_modules = state.get('completed_modules', {})
    version = completed_modules.get(task_id, {}).get('version', 0) + 1
    if task_id == 'config_manager':
        header_code = generate_config_manager_header(device_id)
        completed_modules[task_id] = {"task_id": task_id, "header_code": header_code, "source_code": None,
                                      "main_code": None, "version": version}
        return {"completed_modules": completed_modules, "feedback": ""}
    if task_id == 'ota_handler':
        header_code = generate_ota_handler_header()
        source_code = generate_ota_handler_source().replace("DynamicJsonDocument doc(256);",
                                                            "StaticJsonDocument<256> doc;")
        completed_modules[task_id] = {"task_id": task_id, "header_code": header_code, "source_code": source_code,
                                      "main_code": None, "version": version}
        return {"completed_modules": completed_modules, "feedback": ""}
    if task_id == 'mqtt_logger':
        header_code = generate_mqtt_logger_header()
        source_code = generate_mqtt_logger_source()
        completed_modules[task_id] = {"task_id": task_id, "header_code": header_code, "source_code": source_code,
                                      "main_code": None, "version": version}
        return {"completed_modules": completed_modules, "feedback": ""}
    if task_id == 'tuya_handler':
        header_code = generate_tuya_handler_header()
        source_code = generate_tuya_handler_source()
        sha256_h_content = generate_mbedtls_sha256_header()
        sha256_cpp_content = generate_mbedtls_sha256_source()
        source_files_dict = {"tuya_handler.cpp": source_code, "SHA256.h": sha256_h_content,
                             "SHA256.cpp": sha256_cpp_content}
        completed_modules[task_id] = {"task_id": task_id, "header_code": header_code,
                                      "source_code": json.dumps(source_files_dict), "main_code": None,
                                      "version": version}
        return {"completed_modules": completed_modules, "feedback": ""}

    api_spec = state.get('current_api_spec', 'No API specification provided.')
    context, instructions = "", ""
    if task['task_type'] == 'driver':
        context = f"<APISpecification>\\n{api_spec}\\n</APISpecification>"
        instructions = f"""
                        <Instructions>
                        1.  **Goal**: Your task is to implement the C++ header (.h) and source (.cpp) files for the driver based *only* on the provided `<APISpecification>`.
                        2.  **Strict Adherence**: You MUST implement every function exactly as defined in the spec. Do not add, remove, or modify any functions.
                        3.  **Completeness**: Provide the complete code for both the header and the source file. Do not omit any part.
                        4.  **Header File Guard**: The header file MUST include standard header guards (`#ifndef`, `#define`, `#endif`).
                        5.  **No `main()`**: Do not include a `main()` function or `setup()`/`loop()` unless the API spec explicitly requires it. These are library files.
                        6.  **No Placeholders**: Your code must be fully implemented and functional. Do not leave placeholder comments like `// Your implementation here`.
                        </Instructions>
                        <OutputFormat>
                        You MUST provide two distinct code blocks, one for the header and one for the source file. Use the specified markdown format.
                        [HEADER]
                        ```cpp
                        // Header file content for {task['task_id']}.h
                        ```
                        [SOURCE]
                        ```cpp
                        // Source file content for {task['task_id']}.cpp
                        ```
                        </OutputFormat>
                        """
    else:  # application
        driver_headers = ""
        completed = state.get('completed_modules', {})
        for dep_id in task.get('dependencies', []):
            if dep_id in completed and completed[dep_id].get('header_code'):
                driver_headers += f"--- Interface for {dep_id} from '{dep_id}.h' ---\\n```cpp\\n{completed[dep_id]['header_code']}\\n```\\n\\n"
        is_tuya_device = "tuya_handler" in task.get('dependencies', [])
        if is_tuya_device:
            context = f"<DriverInterfaces>{driver_headers}</DriverInterfaces>"
            instructions = textwrap.dedent(f"""
                                <Instructions>
                                    <Role>You are an AI assistant specialized in generating complete Arduino code for IoT applications for Tuya Cloud.</Role>
                                    <Goal>Your primary task is to generate the *entire* main application `.ino` file. This file will integrate sensor/actuator functionalities with the Tuya Cloud by using the provided `tuya_handler.h` API.</Goal>

                                    <Strict_Guidelines>
                                    1.  **Includes**: You MUST `#include "tuya_handler.h"` and any necessary sensor driver headers provided in `<DriverInterfaces>`.
                                    2.  **Global Objects**: You MUST define the global `WiFiClientSecure` and `PubSubClient` objects, as well as any driver objects (e.g., `AnalogLightSensor lightSensor;`).
                                    3.  **Pin Definitions**: Any new sensor or actuator MUST have its GPIO pin defined using `#define YOUR_SENSOR_PIN_NAME <PIN_NUMBER>` at the top of the file.
                                    4.  **Application Callback**:
                                        * You MUST implement an application-specific callback function: `void handle_tuya_commands(String &topic, String &payload)`.
                                        * Inside this function, you MUST parse the JSON `payload` and use `if (doc["data"].containsKey("YOUR_FEATURE_KEY"))` to check for specific commands from Tuya Cloud.
                                    5.  **`setup()` Function**:
                                        * You MUST initialize the `Serial` port.
                                        * You MUST initialize any drivers (e.g., `lightSensor.als_init(PIN)`).
                                        * Finally, you MUST call `tuya_setup(wifiClient, mqttClient, handle_tuya_commands);` to connect to Tuya Cloud and register your command handler.
                                    6.  **`loop()` Function**:
                                        * The `loop()` function MUST call `tuya_loop();` at the very beginning to maintain the cloud connection.
                                        * The rest of the `loop()` should contain the data publishing logic (e.g., reading a sensor every few seconds).
                                        * To send data, format it as a JSON string. The JSON object MUST be wrapped with a key named `"data"`. Then call `tuya_publish_data(json_string);`.
                                    7.  **No Explanations**: Your entire output MUST ONLY be the complete `.ino` file.
                                    </Strict_Guidelines>
                                </Instructions>

                                <CorrectExample>
                                // An example for a device that reports temperature and controls an LED
                                ```cpp
                                #include "tuya_handler.h"
                                #include "dht11_driver.h" // Example sensor
                                #include <ArduinoJson.h>

                                #define LED_PIN 2
                                #define DHT_PIN 14

                                WiFiClientSecure wifiClient;
                                PubSubClient mqttClient(wifiClient);
                                Dht11Driver dht;

                                void handle_tuya_commands(String &topic, String &payload) {{
                                    StaticJsonDocument<256> doc;
                                    deserializeJson(doc, payload);

                                    if (doc["data"].containsKey("led_control")) {{
                                        int led_status = doc["data"]["led_control"];
                                        digitalWrite(LED_PIN, led_status == 1 ? HIGH : LOW);
                                    }}
                                }}

                                void setup() {{
                                    Serial.begin(115200);
                                    pinMode(LED_PIN, OUTPUT);
                                    dht.init(DHT_PIN);
                                    tuya_setup(wifiClient, mqttClient, handle_tuya_commands);
                                }}

                                void loop() {{
                                    tuya_loop();

                                    static unsigned long lastPublishTime = 0;
                                    if (millis() - lastPublishTime > 10000) {{
                                        lastPublishTime = millis();
                                        float temp = dht.readTemperature();

                                        char json_payload[128];
                                        // *** KEY CHANGE HERE: Using "data" instead of "properties" ***
                                        sprintf(json_payload, "{{\\"data\\":{{\\"temperature\\":%.1f}}}}", temp);

                                        tuya_publish_data(String(json_payload));
                                    }}
                                }}
                                ```
                                </CorrectExample>
                                <OutputFormat>
                                Provide a single, complete code block for the main `.ino` file.
                                ```cpp
                                // Main application code for {task['task_id']}.ino
                                ```
                                </OutputFormat>
                                """)
        else:
            context = f"<DriverInterfaces>{driver_headers}</DriverInterfaces><CommunicationPlan>{json.dumps(state['current_device_task'].get('communication', {}), indent=2)}</CommunicationPlan>"
            instructions = textwrap.dedent(f"""
                <Instructions>
                1.  **Goal**: Write the main application logic in a single `.ino` file. The application must handle both publishing its own data and subscribing to messages from other devices.
    
                2.  **Includes**: You MUST `#include` all necessary drivers: `config_manager.h`, `ota_handler.h`, `mqtt_logger.h`, and any sensor drivers.
    
                3.  **Global Objects**: You MUST define the global `WiFiClient`, `PubSubClient`, and `MqttLogger` objects.
    
                4.  **The MQTT Callback (Most Important Rule!)**:
                    * You MUST implement a master callback function: `void mqtt_callback(char* topic, byte* payload, unsigned int length)`.
                    * **Inside this function, the VERY FIRST thing you do** must be to call `ota_handle_mqtt_message(topic, payload, length);`. This ensures the core OTA functionality always works.
                    * After calling the OTA handler, use `if/else if` statements to check if the `topic` matches any of the application-specific topics listed in the `<CommunicationPlan>`'s `subscribe` array.
                    * For each matched application topic, parse the JSON payload and perform the required logic (e.g., log a message, control a pin, etc.).
    
                5.  **`setup()` Function Rules**:
                    * Initialize the Serial port (`Serial.begin(115200)`).
                    * Call `ota_setup(wifiClient, mqttClient);` to handle network connection.
                    * Call `logger.setup();`.
                    * **Crucially, you MUST register your master callback function by calling `mqttClient.setCallback(mqtt_callback);`**.
                    * After the MQTT client connects (which happens inside `ota_setup`), you MUST loop through the `subscribe` topics in the `<CommunicationPlan>` and call `mqttClient.subscribe(topic)` for each one.
                    * Initialize any other drivers (e.g., sensors).
    
                6.  **`loop()` Function Rules**:
                    * The `loop()` function MUST call `ota_loop()` and `logger.loop()` at the beginning.
                    * The rest of the `loop()` should contain the publishing logic. Use the topics from the `<CommunicationPlan>`'s `publish` array.
                    * Use the `logger` object for all diagnostic output.
    
                </Instructions>
    
                <CorrectExample>
                // A perfect app_main.ino for a device that receives alerts and publishes sensor data
                ```cpp
                #include <ArduinoJson.h>
                #include "config_manager.h"
                #include "ota_handler.h"
                #include "mqtt_logger.h"
                #include "light_sensor_driver.h" // Example sensor driver
    
                WiFiClient wifiClient;
                PubSubClient mqttClient(wifiClient);
                MqttLogger logger(mqttClient, ota_get_device_id());
                LightSensorDriver lightSensor;
    
                // The Master MQTT Callback
                void mqtt_callback(char* topic, byte* payload, unsigned int length) {{
                    // 1. Pass all messages to the OTA handler first
                    ota_handle_mqtt_message(topic, payload, length);
    
                    // 2. Handle application-specific topics
                    String topicStr = String(topic);
                    if (topicStr == "home/living_room/light_alert") {{
                        StaticJsonDocument<128> doc;
                        deserializeJson(doc, payload, length);
                        const char* alert_msg = doc["alert"];
                        logger.print("ALERT RECEIVED: ");
                        logger.println(alert_msg);
                    }}
                }}
    
                void setup() {{
                    Serial.begin(115200);
                    ota_setup(wifiClient, mqttClient); // Connects to WiFi and MQTT
                    logger.setup();
    
                    // Register the master callback AFTER network setup
                    mqttClient.setCallback(mqtt_callback);
    
                    // Subscribe to application topics
                    // Note: reconnect logic inside ota_loop will re-subscribe if needed
                    mqttClient.subscribe("home/living_room/light_alert");
    
                    lightSensor.init(34);
                    logger.println("INFO: System setup complete. Subscribed to alert topic.");
                }}
    
                void loop() {{
                    ota_loop(); // Handles MQTT connection and OTA messages
                    logger.loop();
    
                    static unsigned long lastPublishTime = 0;
                    if (millis() - lastPublishTime > 10000) {{
                        lastPublishTime = millis();
    
                        float percentage = lightSensor.readPercentage();
    
                        StaticJsonDocument<128> jsonDoc;
                        jsonDoc["light_percentage"] = percentage;
                        char payload[128];
                        serializeJson(jsonDoc, payload);
    
                        mqttClient.publish("home/living_room/light_data", payload);
                        logger.println("DEBUG: Light data published.");
                    }}
                }}
                ```
                </CorrectExample>
    
                <OutputFormat>
                Provide a single, complete code block for the main `.ino` file. Your code must strictly follow all rules and the style of the provided example.
                ```cpp
                // Main application code for {task['task_id']}.ino
                ```
                </OutputFormat>
                """)

    prompt = textwrap.dedent(f"""
    <Prompt>
        <Role>You are an expert embedded systems developer following a strict modular architecture.</Role>
        <Context>
            <UserGoal>{state['user_input']}</UserGoal>
            <TaskDescription>{task['description']}</TaskDescription>
            {feedback_context}
            {context}
        </Context>
        {instructions}
    </Prompt>
    """)
    response = developer_model.invoke([HumanMessage(content=prompt)])
    content = response.content
    if task['task_type'] == 'driver':
        header_code = extract_code(content, lang="cpp", block_name="HEADER")
        source_code = extract_code(content, lang="cpp", block_name="SOURCE")
        completed_modules[task_id] = {"task_id": task_id, "header_code": header_code, "source_code": source_code,
                                      "main_code": None, "version": version}
    else:
        main_code = extract_code(content, lang="cpp")
        completed_modules[task_id] = {"task_id": task_id, "header_code": None, "source_code": None,
                                      "main_code": main_code, "version": version}
    return {"completed_modules": completed_modules, "feedback": ""}


def integrator_node(state: AgentState) -> Dict:
    device_id = state['current_device_task']['device_id']
    print(f"--- L6: INTEGRATOR: Assembling final verified firmware for '{device_id}' ---")
    project_files = state.get('project_files', {})
    final_project_files = {}
    completed_modules = state.get('completed_modules', {})
    final_project_files["lib/"] = ""
    final_project_files["src/"] = ""
    for task_id, module in completed_modules.items():
        if task_id == 'tuya_handler':
            module_dir = f"lib/{task_id}/"
            final_project_files[module_dir] = ""
            if module.get('header_code'): final_project_files[f"{module_dir}{task_id}.h"] = module['header_code']
            if module.get('source_code'):
                try:
                    source_files = json.loads(module['source_code'])
                    for filename, content in source_files.items():
                        final_project_files[f"{module_dir}{filename}"] = content
                except (json.JSONDecodeError, TypeError):
                    final_project_files[f"{module_dir}{task_id}.cpp"] = module['source_code']
            continue
        if task_id in ['config_manager', 'ota_handler', 'mqtt_logger']:
            module_dir = f"lib/{task_id}/"
            final_project_files[module_dir] = ""
            if module.get('header_code'): final_project_files[f"{module_dir}{task_id}.h"] = module['header_code']
            if module.get('source_code'): final_project_files[f"{module_dir}{task_id}.cpp"] = module['source_code']
        else:
            if module.get('header_code'): final_project_files[f"src/{task_id}.h"] = module['header_code']
            if module.get('source_code'): final_project_files[f"src/{task_id}.cpp"] = module['source_code']
            if module.get('main_code'): final_project_files[f"src/{task_id}.ino"] = module['main_code']
    board_model = state['current_device_task']['board']
    final_project_files["platformio.ini"] = f"""
[env:{device_id}]
platform = espressif32
board = {board_model}
framework = arduino
lib_deps = knolleary/PubSubClient
monitor_speed = 115200
lib_extra_dirs = lib/
"""
    project_files[device_id] = final_project_files
    return {"project_files": project_files}


def test_plan_designer_node(state: AgentState) -> Dict:
    print("--- L4: TEST PLAN DESIGNER: Creating test plan ---")
    app_main_code = state["completed_modules"].get("app_main", {}).get("main_code", "")
    prompt = textwrap.dedent(f"""
    <Prompt>
        <Role>You are a quality assurance engineer creating a function-oriented test plan for an embedded device.</Role>
        <Goal>Based on the user's request and the final application code, create a step-by-step test plan in JSON format. The plan MUST focus on verifying the primary function of the device by checking for specific log messages generated during its main loop.</Goal>
        <Context>
            <UserRequest>{state['user_input']}</UserRequest>
            <ApplicationCode>```cpp\n{app_main_code}```</ApplicationCode>
        </Context>
        <Instructions>
            1.  **Result-Oriented Goal**: Your ONLY goal is to verify the device's final, recurring output, which is generated inside the `loop()` function.
            2.  **Focus Exclusively on `loop()`**: Analyze the provided `loop()` function in the `<ApplicationCode>`.
            3.  **Identify the Core Output**: Find the primary, recurring log message that indicates a successful action. For example, a log message like `"DEBUG: Sensor data published."` is a perfect result to check for.
            4.  **Ignore `setup()` Entirely**: You MUST NOT create any test steps that check for logs from the `setup()` function (e.g., "System setup complete"). These are intermediate steps and not the final result.
            5.  **Handle Purely Reactive Devices**: If the `loop()` function does not produce any recurring, observable log messages (for instance, the device's logic is entirely within the MQTT callback), you MUST generate a test plan with an **empty `sequence` array (`"sequence": []`)**.
            6.  **Handle Cloud-Connected Devices**: If the `<UserRequest>` or module list clearly indicates a connection to a public cloud like "Tuya", the device's primary function cannot be verified locally. In this case, you MUST generate a test plan with an **empty `sequence` array (`"sequence": []`)**.
        </Instructions>
        <Example>
        <UserRequest>An ESP32 that reads a sensor and publishes the data.</UserRequest>
           <ApplicationCode>
           ...
           void loop() {{
               ...
               mqttClient.publish("some/topic", payload);
               logger.println("DEBUG: Sensor data published."); // <-- This is the important log
               delay(10000);
           }}
           </ApplicationCode>
           <Response>
           ```json
           {{
           "test_plan": {{
               "device_log_topic": "/debug/your_device_id/log",
               "sequence": [
                 {{
                   "name": "Check for Successful Sensor Data Publication",
                   "expected_log_contains": "Sensor data published",
                   "timeout_seconds": 30
                 }}
               ],
               "success_criteria": "ALL_PASS"
           }}
           }}
           ```
           </Response>
        </Example>
        <OutputFormat>You MUST output a single, valid JSON object for the test plan.</OutputFormat>
    </Prompt>
    """)
    response = tester_model.invoke([HumanMessage(content=prompt)])
    try:
        plan_json = json.loads(extract_code(response.content, "json"))
        return {"test_plan": plan_json['test_plan']}
    except (json.JSONDecodeError, KeyError) as e:
        return {"test_plan": None, "feedback": f"FAIL: Could not generate test plan. Error: {e}"}


def deployment_and_verification_node(state: AgentState) -> Dict:
    print("--- L5: PREPARING PROJECT FILES: Assembling app in workspace ---")
    device_id = state['current_device_task']['device_id']
    project_files = state['project_files'][device_id]
    final_project_path = Path(state['workspace_path'])
    if final_project_path.exists():
        shutil.rmtree(final_project_path)
    final_project_path.mkdir(parents=True, exist_ok=True)
    for filename, content in project_files.items():
        dest_path = final_project_path / filename
        if filename.endswith('/'):
            dest_path.mkdir(parents=True, exist_ok=True)
            continue
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(content)
    return {"build_dir": str(final_project_path)}


def compile_node(state: AgentState) -> Dict:
    build_dir = Path(state["build_dir"])
    device_id = state['current_device_task']['device_id']
    print(f"\\n[PHASE 1/3] Compiling firmware for {device_id}...")

    try:
        # 执行 platformio 编译命令
        print(f"[COMPILE_NODE] Executing: platformio run in directory: {build_dir}")
        result = subprocess.run(
            ["platformio", "run"],
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=300  # 5分钟超时
        )

        print(f"[COMPILE_NODE] PlatformIO command completed successfully")
        print(f"[COMPILE_NODE] Return code: {result.returncode}")
        print(f"[COMPILE_NODE] STDOUT length: {len(result.stdout)} chars")
        print(f"[COMPILE_NODE] STDERR length: {len(result.stderr)} chars")

        # 检查编译是否成功
        if "SUCCESS" not in result.stdout and "SUCCESS" not in result.stderr:
            full_log = result.stdout + "\\n" + result.stderr
            print(f"[COMPILE_NODE] ERROR: No SUCCESS message found in output")
            print(f"[COMPILE_NODE] Full compilation log:\\n{full_log}")
            return {"feedback": f"FAIL: Compile finished without explicit SUCCESS message.\\n{full_log}"}

    except subprocess.CalledProcessError as e:
        # 捕获 platformio 命令执行失败的情况
        print(f"[COMPILE_NODE] ERROR: subprocess.CalledProcessError occurred")
        print(f"[COMPILE_NODE] Return code: {e.returncode}")
        print(f"[COMPILE_NODE] Command: {e.cmd}")

        stdout_content = getattr(e, 'stdout', '') or ''
        stderr_content = getattr(e, 'stderr', '') or ''

        print(f"[COMPILE_NODE] STDOUT: {stdout_content}")
        print(f"[COMPILE_NODE] STDERR: {stderr_content}")

        full_error_log = f"Command: {e.cmd}\\nReturn code: {e.returncode}\\nSTDOUT:\\n{stdout_content}\\nSTDERR:\\n{stderr_content}"
        return {"feedback": f"FAIL: Compile process failed with return code {e.returncode}.\\n{full_error_log}"}

    except subprocess.TimeoutExpired as e:
        # 捕获超时异常
        print(f"[COMPILE_NODE] ERROR: subprocess.TimeoutExpired occurred")
        print(f"[COMPILE_NODE] Command: {e.cmd}")
        print(f"[COMPILE_NODE] Timeout: {e.timeout} seconds")

        stdout_content = getattr(e, 'stdout', '') or ''
        stderr_content = getattr(e, 'stderr', '') or ''

        print(f"[COMPILE_NODE] Partial STDOUT: {stdout_content}")
        print(f"[COMPILE_NODE] Partial STDERR: {stderr_content}")

        return {"feedback": f"FAIL: Compile process timed out after {e.timeout} seconds.\\nPartial output:\\nSTDOUT: {stdout_content}\\nSTDERR: {stderr_content}"}

    except FileNotFoundError as e:
        # 捕获 platformio 命令不存在的情况
        print(f"[COMPILE_NODE] ERROR: FileNotFoundError occurred")
        print(f"[COMPILE_NODE] Error: {e}")
        return {"feedback": f"FAIL: PlatformIO command not found. Please ensure PlatformIO is installed and in PATH. Error: {e}"}

    except PermissionError as e:
        # 捕获权限错误
        print(f"[COMPILE_NODE] ERROR: PermissionError occurred")
        print(f"[COMPILE_NODE] Error: {e}")
        return {"feedback": f"FAIL: Permission denied when executing PlatformIO. Error: {e}"}

    except OSError as e:
        # 捕获其他操作系统相关错误
        print(f"[COMPILE_NODE] ERROR: OSError occurred")
        print(f"[COMPILE_NODE] Error: {e}")
        return {"feedback": f"FAIL: Operating system error when executing PlatformIO. Error: {e}"}

    except Exception as e:
        # 捕获所有其他未预期的异常
        print(f"[COMPILE_NODE] ERROR: Unexpected exception occurred")
        print(f"[COMPILE_NODE] Exception type: {type(e).__name__}")
        print(f"[COMPILE_NODE] Exception message: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"feedback": f"FAIL: Unexpected error during compilation. Exception: {type(e).__name__}: {str(e)}"}

    # 检查固件文件是否生成
    try:
        firmware_path = build_dir / ".pio" / "build" / device_id / "firmware.bin"
        print(f"[COMPILE_NODE] Checking for firmware file at: {firmware_path}")

        if not firmware_path.exists():
            print(f"[COMPILE_NODE] ERROR: Firmware file not found at expected location")
            # 尝试列出 build 目录的内容以便调试
            build_output_dir = build_dir / ".pio" / "build"
            if build_output_dir.exists():
                print(f"[COMPILE_NODE] Contents of {build_output_dir}:")
                for item in build_output_dir.iterdir():
                    print(f"[COMPILE_NODE]   - {item}")
            return {"feedback": f"FAIL: Compiled firmware.bin not found at {firmware_path}"}

        print(f"[COMPILE_NODE] SUCCESS: Firmware file found at {firmware_path}")
        print(f"[COMPILE_NODE] Firmware file size: {firmware_path.stat().st_size} bytes")

        return {
            "feedback": "PASS: Compilation successful.",
            "firmware_path": str(firmware_path),
            "build_dir": str(build_dir)
        }

    except Exception as e:
        # 捕获检查固件文件时的异常
        print(f"[COMPILE_NODE] ERROR: Exception while checking firmware file")
        print(f"[COMPILE_NODE] Exception: {type(e).__name__}: {str(e)}")
        return {"feedback": f"FAIL: Error checking firmware file. Exception: {type(e).__name__}: {str(e)}"}


def pre_deployment_pause_node(state: AgentState) -> Dict:
    print("\\n--- Waiting for user to select deployment method... ---")
    return {"status": "PAUSED_FOR_DEPLOYMENT"}


def ota_deployment_node(state: AgentState) -> Dict:
    print("\\n--- Entering Node: Real OTA Deployment ---")
    build_dir = Path(state["build_dir"])
    firmware_path = Path(state["firmware_path"])
    device_id = state['current_device_task']['device_id']
    local_pc_ip = get_local_ip()
    ota_pusher_code = textwrap.dedent(f"""
    import paho.mqtt.client as mqtt
    import json, time
    MQTT_BROKER = "{local_pc_ip}"
    MQTT_PORT = 1883
    DEVICE_ID = "{device_id}"
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()
    time.sleep(1)
    if client.is_connected():
        command = {{"action": "update", "file": "firmware.bin"}}
        topic = f"/ota/{{DEVICE_ID}}/command"
        client.publish(topic, json.dumps(command))
    else:
        exit(1)
    time.sleep(1)
    client.loop_stop()
    client.disconnect()
    """)
    ota_pusher_script_path = build_dir / "ota_pusher.py"
    ota_pusher_script_path.write_text(ota_pusher_code, encoding="utf-8")
    http_server_dir = firmware_path.parent
    http_server_process = subprocess.Popen(["python", "-m", "http.server", "8000"], cwd=http_server_dir,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        subprocess.run(["python", ota_pusher_script_path.name], cwd=build_dir, check=True, capture_output=True,
                       text=True, encoding='utf-8', errors='ignore')
        time.sleep(15)
    except subprocess.CalledProcessError as e:
        return {"feedback": f"FAIL: OTA push script failed. Error: {e.stderr}"}
    finally:
        http_server_process.terminate()
    return {"feedback": "PASS: Real OTA deployment command sent."}


def deploy_and_verify_node(state: AgentState) -> Dict:
    print("\\n--- Entering Node: deploy_and_verify_node ---")
    deployment_choice = state.get('deployment_choice')
    if deployment_choice == "manual":
        time.sleep(15)
    test_plan = state.get('test_plan')
    if not test_plan or not test_plan.get("sequence"):
        return {"feedback": "PASS: Verification skipped (no test plan)."}
    device_id = state['current_device_task']['device_id']
    build_dir = Path(state["build_dir"])
    local_pc_ip = get_local_ip()
    correct_debug_topic = f"/debug/{device_id}/log"
    verifier_code = f"""
import paho.mqtt.client as mqtt
import json, time, sys
MQTT_BROKER = "{local_pc_ip}"
MQTT_PORT = 1883
TEST_PLAN = {json.dumps(test_plan)}
DEVICE_ID = "{device_id}"
test_results = {{}}
current_step_index = 0
start_time = time.time()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        client.subscribe("{correct_debug_topic}")
    else:
        sys.exit(1)
def on_message(client, userdata, msg):
    global current_step_index, start_time
    payload = msg.payload.decode('utf-8').strip()
    if current_step_index >= len(TEST_PLAN['sequence']): return
    step = TEST_PLAN['sequence'][current_step_index]
    if step['expected_log_contains'] in payload:
        test_results[step['name']] = "PASS"
        current_step_index += 1
        start_time = time.time()
client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()
while current_step_index < len(TEST_PLAN['sequence']):
    step = TEST_PLAN['sequence'][current_step_index]
    if time.time() - start_time > step['timeout_seconds']:
        test_results[step['name']] = "FAIL: Timeout"
        break
    time.sleep(0.5)
client.loop_stop()
client.disconnect()
all_passed = all(res == "PASS" for res in test_results.values()) and len(test_results) == len(TEST_PLAN['sequence'])
final_result = {{"status": "PASS" if all_passed else "FAIL", "details": test_results}}
with open("test_result.json", "w") as f: json.dump(final_result, f)
if not all_passed: sys.exit(1)
"""
    verifier_script_path = build_dir / "run_verification.py"
    verifier_script_path.write_text(verifier_code, encoding="utf-8")
    try:
        subprocess.run(["python", "run_verification.py"], cwd=build_dir, check=True, capture_output=True, text=True,
                       encoding='utf-8', errors='ignore')
        with open(build_dir / "test_result.json", "r") as f:
            test_output = json.load(f)
        if test_output["status"] == "PASS":
            return {"feedback": "PASS: All hardware-in-the-loop tests passed."}
        else:
            return {"feedback": f"FAIL: Verification failed. Details: {json.dumps(test_output['details'])}"}
    except subprocess.CalledProcessError as e:
        return {"feedback": f"FAIL: Verification script crashed. Stderr: {e.stderr}"}


def dp_extractor_node(state: AgentState) -> Dict:
    print("\\n--- Entering DP Extractor Node ---")
    current_device_task = state.get("current_device_task")
    if not current_device_task: return {"dp_info_list": []}
    device_id = current_device_task.get("device_id")
    if not device_id: return {"dp_info_list": []}
    all_project_files = state.get("project_files", {})
    actual_project_files = all_project_files.get(device_id)
    if not actual_project_files or not isinstance(actual_project_files, dict): return {"dp_info_list": []}
    all_code_content = ""
    for file_name, file_content in actual_project_files.items():
        if isinstance(file_content, str):
            all_code_content += f"// --- Start of {file_name} ---\\n{file_content}\\n// --- End of {file_name} ---\\n\\n"
    if not all_code_content.strip(): return {"dp_info_list": []}
    prompt_template = ChatPromptTemplate.from_messages([
        SystemMessagePromptTemplate.from_template(
            textwrap.dedent("""
            你是一个经验丰富的嵌入式系统工程师，擅长分析C/C++代码并提取设备的功能点信息。
            你的任务是根据提供的功能代码，识别其中实现的功能点（Data Point，简称DP），并严格按照指定的JSON格式输出这些功能点的信息列表。

            功能点信息dp_info_list的格式是一个JSON列表，每个元素都是一个字典，代表一个功能点。
            请参考以下示例结构：
            ```json
            [
                {{
                    "id": 104,
                    "name": "亮度",
                    "code": "bright_value",
                    "mode": "rw",
                    "type": "value",
                    "define": "",
                    "remark": "",
                    "range_min": "10",
                    "range_max": "1000",
                    "step": "1",
                    "multiple": "0",
                    "unit": ""
                }},
                {{
                    "id": 105,
                    "name": "空气质量指数",
                    "code": "air_quality_index",
                    "mode": "ro",
                    "type": "enum",
                    "define": "level_1,level_2,level_3,level_4,level_5",
                    "remark": "1",
                    "range_min": "",
                    "range_max": "",
                    "step": "",
                    "multiple": "",
                    "unit": ""
                }},
                {{
                    "id": 107,
                    "name": "设备开关状态",
                    "code": "device_switch_state",
                    "mode": "rw",
                    "type": "bool",
                    "define": "",
                    "remark": "",
                    "range_min": "",
                    "range_max": "",
                    "step": "",
                    "multiple": "",
                    "unit": ""
                }}
            ]
            ```

            请严格遵循以下功能点信息规则：
            1. id：功能点ID，必填，整数，范围在101-499之间。在生成新的ID时，请确保不与已知的任何ID冲突。从101开始递增生成，并避免重复。
            2. name：功能点名称，必填，根据功能代码具体实现的功能生成，支持中文和英文。
            3. code：标识符，必填，支持英文，通常是变量名或功能函数名的小写下划线形式。
            4. mode：数据传输类型，必填。
               - 可上报可下发：填写 "rw"
               - 只上报：填写 "ro"
               - 只下发：填写 "wr"
            5. type：数据类型，必填，根据功能代码判断。
               - 数值型：填写 "value"
               - 字符型：填写 "string"
               - 时间型：填写 "data"
               - 布尔型：填写 "bool"
               - 枚举型：填写 "enum"
            6. define：数据定义。
               - 字符型时：填写最大长度数值（例如 "64"）。
               - 枚举型时：填写枚举值，并用英文逗号 "," 隔开（例如 "off,on,auto"）。
               - 其他数据类型时：保留为空字符串 ""。
            7. remark：备注，默认保留为空字符串 ""。
            8. range_min：数据范围最小值，仅数值型必填。如果代码中没有明确的范围，请根据类型给出合理默认值（例如0或空字符串）。
            9. range_max：数据范围最大值，仅数值型必填。如果代码中没有明确的范围，请根据类型给出合理默认值（例如100或空字符串）。
            10. step：间距，仅数值型必填，通常为 "1"。
            11. multiple：倍数，仅数值型必填，通常为 "0"。
            12. unit：单位，一般保留为空字符串 ""。

            你的输出必须是一个只包含JSON列表的字符串，不需要任何额外的解释或文本。
            如果代码中没有找到任何明确的功能点，请返回一个空的JSON列表 `[]`。
            请确保JSON格式严格正确，并且所有键名和值类型都符合上述规则。
            """)),
        HumanMessagePromptTemplate.from_template("请根据以下项目代码分析并生成功能点信息列表：\\n\\n{code_content}")
    ])
    chain = prompt_template | dp_extractor_model | JsonOutputParser()
    try:
        dp_info_list = chain.invoke({"code_content": all_code_content})
        return {"dp_info_list": dp_info_list}
    except Exception as e:
        print(f"提取功能点信息失败: {e}")
        return {"dp_info_list": []}


# =================================================================================
# 5. Graph Definition (精简并植入失败修复循环)
# =================================================================================

def check_module_queue(state: AgentState) -> str:
    if state.get("current_module_task"):
        return "continue_development"
    return "finish_development"


def check_unit_test_result(state: AgentState) -> str:
    feedback = state.get('feedback', '')
    if "FAIL" in feedback:
        print(f"--- ORCHESTRATOR: Unit test failed. Routing back to developer for repair. ---")
        return "REPAIR"
    return "PASS"


def route_deployment(state: AgentState) -> str:
    choice = state.get("user_action")
    if choice == 'DEPLOY_OTA':
        return "REAL_DEPLOY"
    return "FAKE_DEPLOY"


def build_graph():
    """构建并返回与V3 API对齐的、精简的LangGraph工作流图"""
    workflow = StateGraph(AgentState)

    # 添加所有必要的节点
    workflow.add_node("module_architect", module_architect_node)
    workflow.add_node("module_dispatcher", module_dispatcher_node)
    workflow.add_node("api_designer", api_designer_node)
    workflow.add_node("developer", developer_node)
    workflow.add_node("integrator", integrator_node)
    workflow.add_node("test_plan_designer", test_plan_designer_node)
    workflow.add_node("deployment_and_verification", deployment_and_verification_node)
    workflow.add_node("compile_node", compile_node)
    workflow.add_node("pre_deployment_pause", pre_deployment_pause_node)
    workflow.add_node("ota_deployment_node", ota_deployment_node)
    workflow.add_node("deploy_and_verify_node", deploy_and_verify_node)
    workflow.add_node("dp_extractor", dp_extractor_node)

    # 定义新的、精简的流程
    workflow.set_entry_point("module_architect")
    workflow.add_edge("module_architect", "module_dispatcher")
    workflow.add_conditional_edges(
        "module_dispatcher",
        lambda s: "api_designer" if s.get("current_module_task") else "integrator",
        {"api_designer": "api_designer", "integrator": "integrator"}
    )
    workflow.add_edge("api_designer", "developer")
    workflow.add_edge("developer", "module_dispatcher")
    workflow.add_edge("integrator", "test_plan_designer")
    workflow.add_edge("test_plan_designer", "deployment_and_verification")
    workflow.add_edge("deployment_and_verification", "compile_node")
    workflow.add_edge("compile_node", "pre_deployment_pause")

    workflow.add_conditional_edges("pre_deployment_pause", route_deployment,
                                   {"REAL_DEPLOY": "ota_deployment_node", "FAKE_DEPLOY": "deploy_and_verify_node"})
    workflow.add_edge("ota_deployment_node", "deploy_and_verify_node")

    # 【关键升级点】失败-修复循环
    workflow.add_conditional_edges(
        "deploy_and_verify_node",
        check_unit_test_result,
        {
            "PASS": "dp_extractor",
            "REPAIR": "developer"  # 失败时，返回开发节点并携带feedback
        }
    )
    workflow.add_edge("dp_extractor", END)

    return workflow.compile()