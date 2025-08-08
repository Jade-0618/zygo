# analyzer_test_script.py
# -*- coding: utf-8 -*-

import requests
import json

# --- 配置 ---
BASE_URL = "http://127.0.0.1:5000/api/v1"
USER_CREDENTIALS = {
    "username": "testuser",
    "password": "password123"
}
# 要分析的自然语言文本
ANALYSIS_TEXT = "我想做一个能用手机控制开关的智能插座，它需要连接到家里的WiFi，并使用一个继电器模块来控制电源。"

def run_analyzer_test():
    """执行完整的分析器接口测试流程"""
    session = requests.Session()
    access_token = None

    # --- 1. 登录并获取Token ---
    print("--- 步骤 1: 登录并获取Token ---")
    login_url = f"{BASE_URL}/auth/login"
    try:
        response = session.post(login_url, json=USER_CREDENTIALS)
        response.raise_for_status()  # 如果请求失败 (非2xx状态码), 则抛出异常

        login_data = response.json()
        access_token = login_data.get("access_token")
        if not access_token:
            print(" 登录失败: 未在响应中找到 access_token。")
            return

        print(f" 登录成功! 获取到Token。")

    except requests.exceptions.RequestException as e:
        print(f" 登录请求失败: {e}")
        # 尝试打印更详细的错误信息
        try:
            print(f"   服务器返回: {e.response.json()}")
        except:
            pass
        return

    # --- 2. 调用分析接口 ---
    print("\n--- 步骤 2: 调用项目分析接口 ---")
    analyze_url = f"{BASE_URL}/projects/analyze"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    payload = {
        "raw_text": ANALYSIS_TEXT
    }
    try:
        response = session.post(analyze_url, json=payload, headers=headers)
        response.raise_for_status()

        analysis_result = response.json()
        print(" 分析接口调用成功!")
        print("--- 分析结果 ---")
        # 使用json.dumps美化输出
        print(json.dumps(analysis_result, indent=2, ensure_ascii=False))
        print("--------------------")

    except requests.exceptions.RequestException as e:
        print(f" 分析接口请求失败: {e}")
        try:
            print(f"   服务器返回: {e.response.json()}")
        except:
            pass
        return

    print("\n🎉 验证流程执行完毕。")


if __name__ == "__main__":
    run_analyzer_test()
