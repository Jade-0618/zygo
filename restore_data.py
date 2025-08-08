#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据恢复脚本
从备份数据库恢复用户数据，并迁移到包含MQTT字段的新数据库结构
"""

import sqlite3
import os
from datetime import datetime

def restore_data_from_backup():
    """从备份恢复数据"""
    backup_db = 'dev-db-backup.sqlite'
    current_db = 'dev-db.sqlite'
    
    if not os.path.exists(backup_db):
        print(f"备份文件 {backup_db} 不存在！")
        return False
    
    print(f"开始从 {backup_db} 恢复数据到 {current_db}")
    
    # 连接到两个数据库
    backup_conn = sqlite3.connect(backup_db)
    current_conn = sqlite3.connect(current_db)
    
    backup_cursor = backup_conn.cursor()
    current_cursor = current_conn.cursor()

    try:
        # 1. 恢复用户数据
        print("恢复用户数据...")
        backup_cursor.execute("SELECT * FROM users")
        users = backup_cursor.fetchall()

        # 获取users表的列信息
        backup_cursor.execute("PRAGMA table_info(users)")
        user_columns = [row[1] for row in backup_cursor.fetchall()]
        print(f"用户表列: {user_columns}")

        for user in users:
            # 构建插入语句
            placeholders = ','.join(['?' for _ in user])
            columns = ','.join(user_columns)
            current_cursor.execute(f"INSERT OR REPLACE INTO users ({columns}) VALUES ({placeholders})", user)
            print(f"恢复用户: {user[1] if len(user) > 1 else 'Unknown'}")  # username

        # 2. 恢复设备数据
        print("恢复设备数据...")
        backup_cursor.execute("SELECT * FROM devices")
        devices = backup_cursor.fetchall()

        # 获取备份数据库中devices表的列信息
        backup_cursor.execute("PRAGMA table_info(devices)")
        backup_device_columns = [row[1] for row in backup_cursor.fetchall()] 
        print(f"备份设备表列: {backup_device_columns}")

        # 获取当前数据库中devices表的列信息
        current_cursor.execute("PRAGMA table_info(devices)")
        current_device_columns = [row[1] for row in current_cursor.fetchall()]
        print(f"当前设备表列: {current_device_columns}")

        for device in devices:
            # 创建设备数据字典
            device_data = {}
            for i, col in enumerate(backup_device_columns):
                if i < len(device):
                    device_data[col] = device[i]

            # 为新的MQTT字段设置默认值
            mqtt_defaults = {
                'mqtt_broker_host': None,
                'mqtt_broker_port': 1883,
                'mqtt_username': None,
                'mqtt_password': None,
                'mqtt_client_id': None,
                'mqtt_subscribe_topics': None,
                'mqtt_monitoring_enabled': 0
            }

            # 添加MQTT字段的默认值
            for mqtt_field, default_value in mqtt_defaults.items():
                if mqtt_field not in device_data:
                    device_data[mqtt_field] = default_value

            # 构建插入语句，只包含当前表中存在的列
            insert_columns = []
            insert_values = []
            for col in current_device_columns:
                if col in device_data:
                    insert_columns.append(col)
                    insert_values.append(device_data[col])

            placeholders = ','.join(['?' for _ in insert_values])
            columns_str = ','.join(insert_columns)
            current_cursor.execute(f"INSERT OR REPLACE INTO devices ({columns_str}) VALUES ({placeholders})", insert_values)

            device_name = device_data.get('nickname', 'Unknown')
            device_id = device_data.get('internal_device_id', 'Unknown')     
            print(f"恢复设备: {device_name} (ID: {device_id})")

        # 3. 恢复项目数据
        print("恢复项目数据...")
        backup_cursor.execute("SELECT * FROM projects")
        projects = backup_cursor.fetchall()

        backup_cursor.execute("PRAGMA table_info(projects)")
        project_columns = [row[1] for row in backup_cursor.fetchall()]       

        for project in projects:
            placeholders = ','.join(['?' for _ in project])
            columns = ','.join(project_columns)
            current_cursor.execute(f"INSERT OR REPLACE INTO projects ({columns}) VALUES ({placeholders})", project)
            print(f"恢复项目: {project[1] if len(project) > 1 else 'Unknown'}")  # name

        # 4. 恢复工作流状态数据
        print("恢复工作流状态数据...")
        backup_cursor.execute("SELECT * FROM workflow_states")
        workflows = backup_cursor.fetchall()

        backup_cursor.execute("PRAGMA table_info(workflow_states)")
        workflow_columns = [row[1] for row in backup_cursor.fetchall()]      

        for workflow in workflows:
            placeholders = ','.join(['?' for _ in workflow])
            columns = ','.join(workflow_columns)
            current_cursor.execute(f"INSERT OR REPLACE INTO workflow_states ({columns}) VALUES ({placeholders})", workflow)
            print(f"恢复工作流: {workflow[0] if len(workflow) > 0 else 'Unknown'}")  # workflow_id

        # 提交更改
        current_conn.commit()
        print("数据恢复完成！")

        # 验证恢复结果
        print("\n验证恢复结果:")
        current_cursor.execute("SELECT COUNT(*) FROM users")
        print(f"用户数量: {current_cursor.fetchone()[0]}")

        current_cursor.execute("SELECT COUNT(*) FROM devices")
        print(f"设备数量: {current_cursor.fetchone()[0]}")

        current_cursor.execute("SELECT COUNT(*) FROM projects")
        print(f"项目数量: {current_cursor.fetchone()[0]}")

        current_cursor.execute("SELECT COUNT(*) FROM workflow_states")       
        print(f"工作流数量: {current_cursor.fetchone()[0]}")

        # 显示用户信息
        current_cursor.execute("SELECT username FROM users")
        usernames = [row[0] for row in current_cursor.fetchall()]
        print(f"恢复的用户: {usernames}")

        # 显示设备信息
        current_cursor.execute("SELECT nickname, internal_device_id FROM devices")
        devices_info = current_cursor.fetchall()
        print("恢复的设备:")
        for device_name, device_id in devices_info:
            print(f"  - {device_name} (ID: {device_id})")

        return True

    except Exception as e:
        current_conn.rollback()
        print(f"数据恢复失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        backup_conn.close()
        current_conn.close()

if __name__ == '__main__':
    success = restore_data_from_backup()
    if success:
        print("\n✅ 数据恢复成功！您现在可以使用原来的账户登录了。")
    else:
        print("\n❌ 数据恢复失败！请检查错误信息。")
