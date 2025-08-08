# 环境变量设置指南

## 概述

为了保护敏感信息（如API密钥），本项目已将所有敏感配置移至环境变量。这样可以防止敏感信息被意外提交到版本控制系统中。

## 设置步骤

### 1. 复制环境变量模板

```bash
cp .env.example .env
```

### 2. 编辑 .env 文件

打开 `.env` 文件并填入实际的配置值：

```bash
# LangChain API 配置
LANGCHAIN_API_KEY=your_actual_api_key_here
LANGCHAIN_BASE_URL=https://ark.cn-beijing.volces.com/api/v3

# Flask 应用配置
SECRET_KEY=your_secret_key_here
FLASK_ENV=development

# 数据库配置
DEV_DATABASE_URL=sqlite:///dev-db.sqlite
TEST_DATABASE_URL=sqlite://
DATABASE_URL=sqlite:///data.sqlite
```

### 3. 重要提醒

- **不要提交 .env 文件到版本控制系统**：`.env` 文件已被添加到 `.gitignore` 中
- **保护你的API密钥**：不要在代码中硬编码API密钥
- **团队协作**：团队成员需要各自创建自己的 `.env` 文件

## 环境变量说明

| 变量名 | 描述 | 必需 | 默认值 |
|--------|------|------|--------|
| `LANGCHAIN_API_KEY` | LangChain API密钥 | 是 | 无 |
| `LANGCHAIN_BASE_URL` | LangChain API基础URL | 否 | https://ark.cn-beijing.volces.com/api/v3 |
| `SECRET_KEY` | Flask应用密钥 | 是 | 无 |
| `FLASK_ENV` | Flask环境 | 否 | development |

## 验证设置

运行应用前，确保环境变量已正确设置：

```bash
python run.py
```

如果看到以下错误，说明环境变量未正确设置：
```
ValueError: LANGCHAIN_API_KEY environment variable is not set. Please set it before running the application.
```

## 安全最佳实践

1. **定期轮换API密钥**
2. **使用不同环境的不同密钥**（开发、测试、生产）
3. **限制API密钥的权限范围**
4. **监控API密钥的使用情况**

## 故障排除

### 问题：应用启动时提示API密钥未设置

**解决方案**：
1. 确认 `.env` 文件存在于项目根目录
2. 确认 `.env` 文件中包含 `LANGCHAIN_API_KEY=your_key_here`
3. 确认没有多余的空格或引号
4. 重启应用

### 问题：python-dotenv 模块未找到

**解决方案**：
```bash
pip install python-dotenv
```
