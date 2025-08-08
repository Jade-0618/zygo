#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据库迁移脚本
用于为现有的Device表添加MQTT相关字段，并创建MqttLog表
"""

import sqlite3
import os
from datetime import datetime

def backup_database(db_path):
    """备份数据库"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if os.path.exists(db_path):
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"数据库已备份到: {backup_path}")
        return backup_path
    return None

def check_table_exists(cursor, table_name):
    """检查表是否存在"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

def check_column_exists(cursor, table_name, column_name):
    """检查列是否存在"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def migrate_database(db_path):
    """执行数据库迁移"""
    print(f"开始迁移数据库: {db_path}")

    # 备份数据库
    backup_path = backup_database(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 检查现有表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")  
        existing_tables = [row[0] for row in cursor.fetchall()]
        print(f"现有表: {existing_tables}")

        # 如果没有任何表，创建所有表
        if not existing_tables:
            print("数据库为空，创建所有表...")
            create_all_tables(cursor)
        else:
            # 执行增量迁移
            print("执行增量迁移...")

            # 1. 为devices表添加MQTT字段
            if check_table_exists(cursor, 'devices'):
                add_mqtt_fields_to_devices(cursor)
            else:
                print("devices表不存在，创建devices表...")
                create_devices_table(cursor)

            # 2. 创建mqtt_logs表
            if not check_table_exists(cursor, 'mqtt_logs'):
                print("创建mqtt_logs表...")
                create_mqtt_logs_table(cursor)
            else:
                print("mqtt_logs表已存在")

            # 3. 创建其他缺失的表
            create_missing_tables(cursor, existing_tables)

        conn.commit()
        print("数据库迁移完成!")

    except Exception as e:
        conn.rollback()
        print(f"迁移失败: {e}")
        if backup_path and os.path.exists(backup_path):
            print(f"可以从备份恢复: {backup_path}")
        raise
    finally:
        conn.close()

def add_mqtt_fields_to_devices(cursor):
    """为devices表添加MQTT相关字段"""
    mqtt_fields = [
        ('mqtt_broker_host', 'VARCHAR(255)'),
        ('mqtt_broker_port', 'INTEGER DEFAULT 1883'),
        ('mqtt_username', 'VARCHAR(64)'),
        ('mqtt_password', 'VARCHAR(64)'),
        ('mqtt_client_id', 'VARCHAR(64)'),
        ('mqtt_subscribe_topics', 'TEXT'),
        ('mqtt_monitoring_enabled', 'BOOLEAN DEFAULT 0')
    ]

    for field_name, field_type in mqtt_fields:
        if not check_column_exists(cursor, 'devices', field_name):
            print(f"添加字段: devices.{field_name}")
            cursor.execute(f"ALTER TABLE devices ADD COLUMN {field_name} {field_type}")
        else:
            print(f"字段已存在: devices.{field_name}")

def create_devices_table(cursor):
    """创建devices表"""
    cursor.execute('''
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            internal_device_id VARCHAR(36) UNIQUE NOT NULL,
            nickname VARCHAR(64) NOT NULL,
            board_model VARCHAR(64) NOT NULL,
            cloud_platform VARCHAR(32) DEFAULT 'tuya',
            cloud_product_id VARCHAR(64),
            cloud_device_id VARCHAR(64),
            cloud_device_secret VARCHAR(64),
            mqtt_broker_host VARCHAR(255),
            mqtt_broker_port INTEGER DEFAULT 1883,
            mqtt_username VARCHAR(64),
            mqtt_password VARCHAR(64),
            mqtt_client_id VARCHAR(64),
            mqtt_subscribe_topics TEXT,
            mqtt_monitoring_enabled BOOLEAN DEFAULT 0,
            peripherals TEXT,
            user_id INTEGER
        )
    ''')
    print("devices表创建完成")

def create_mqtt_logs_table(cursor):
    """创建mqtt_logs表"""
    cursor.execute('''
        CREATE TABLE mqtt_logs (
            id INTEGER PRIMARY KEY,
            device_id VARCHAR(36) NOT NULL,
            topic VARCHAR(255) NOT NULL,
            payload TEXT NOT NULL,
            qos INTEGER DEFAULT 0,
            retain BOOLEAN DEFAULT 0,
            direction VARCHAR(10) NOT NULL DEFAULT 'incoming',
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices (internal_device_id)  
        )
    ''')
    print("mqtt_logs表创建完成")

def create_missing_tables(cursor, existing_tables):
    """创建缺失的表"""
    # 创建users表
    if 'users' not in existing_tables:
        print("创建users表...")
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                wifi_ssid VARCHAR(64),
                wifi_password VARCHAR(64)
            )
        ''')

    # 创建projects表
    if 'projects' not in existing_tables:
        print("创建projects表...")
        cursor.execute('''
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                config_json TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

    # 创建workflow_states表
    if 'workflow_states' not in existing_tables:
        print("创建workflow_states表...")
        cursor.execute('''
            CREATE TABLE workflow_states (
                workflow_id VARCHAR(36) PRIMARY KEY,
                state_json TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                logs TEXT DEFAULT ''
            )
        ''')

def create_all_tables(cursor):
    """创建所有表（用于空数据库）"""
    # 创建users表
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            wifi_ssid VARCHAR(64),
            wifi_password VARCHAR(64)
        )
    ''')

    # 创建devices表
    create_devices_table(cursor)

    # 创建projects表
    cursor.execute('''
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            config_json TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # 创建workflow_states表
    cursor.execute('''
        CREATE TABLE workflow_states (
            workflow_id VARCHAR(36) PRIMARY KEY,
            state_json TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            logs TEXT DEFAULT ''
        )
    ''')

    # 创建mqtt_logs表
    create_mqtt_logs_table(cursor)

    print("所有表创建完成")

if __name__ == '__main__':
    db_path = 'dev-db.sqlite'
    migrate_database(db_path)
