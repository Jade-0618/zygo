# config.py
# 这个文件用于存放我们应用的所有配置。
# 通过使用类来组织配置，我们可以轻松地为不同环境（如开发、测试、生产）提供不同的设置。

import os

# 获取项目根目录的绝对路径
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """
    基础配置类，包含所有环境通用的配置。
    其他特定环境的配置类将继承自这个类。
    """
    # 用于保护表单免受CSRF攻击以及加密session的密钥
    # 在生产环境中，这应该是一个复杂且保密的字符串，并从环境变量加载
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-and-hard-to-guess-string'

    # 数据库配置
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 为将来可能的邮件功能预留配置
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    @staticmethod
    def init_app(app):
        # 这个方法可以用来执行一些应用级别的初始化操作
        pass

class DevelopmentConfig(Config):
    """
    开发环境配置。
    """
    DEBUG = True
    # 开发环境使用SQLite数据库，因为它简单、无需额外服务
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'dev-db.sqlite')

class TestingConfig(Config):
    """
    测试环境配置。
    """
    TESTING = True
    # 测试环境也使用一个独立的SQLite数据库
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite://' # 使用内存数据库

class ProductionConfig(Config):
    """
    生产环境配置。
    """
    # 生产环境通常使用更健壮的数据库，如PostgreSQL或MySQL
    # 其URI应该从环境变量中加载
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')

# 将配置名称与配置类关联起来
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}