"""
配置管理模块
从环境变量读取配置信息
"""
import os
from dataclasses import dataclass
from typing import Optional, List
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()


# 订阅等级常量
class SubscriptionTier:
    FREE = "free"
    PRO = "pro"
    PREMIUM = "premium"
    
    # 所有有效等级
    ALL = [PREMIUM, PRO, FREE]


# 任务状态常量
class TaskStatus:
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# SSL 检查状态常量
class SSLStatus:
    VALID = "valid"
    EXPIRING = "expiring"  # 30 天内过期
    EXPIRED = "expired"
    ERROR = "error"


@dataclass
class Config:
    """应用配置"""
    # 数据库配置
    database_url: str
    
    # 飞书通知配置（管理员通知）
    feishu_webhook_url: str = ""

    # Brevo 邮件 API 配置（支持多个密钥轮询）
    brevo_api_keys: List[str] = None
    brevo_sender_email: str = "noreply@guardssl.info"
    brevo_sender_name: str = "GuardSSL"
    
    # 品牌配置
    brand_name: str = "Guard SSL"
    brand_url: str = "https://guardssl.info"
    dashboard_url: str = "https://guardssl.info/dashboard"
    
    # SSL 检查配置
    ssl_check_timeout: int = 10
    
    # 重试配置
    max_retries: int = 3
    retry_delay: int = 2
    
    # 证书过期预警天数
    expiring_threshold_days: int = 30
    
    # 批处理配置
    batch_size: int = 10           # 每批并发检测的域名数量
    rate_limit_delay: float = 0.1  # 请求间隔（秒），避免过快请求
    max_workers: int = 10          # 最大工作线程数


def load_config() -> Config:
    """
    从环境变量加载配置

    Returns:
        Config: 配置对象

    Raises:
        ValueError: 必需的环境变量未设置
    """
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL 环境变量未设置")

    # 解析 Brevo API 密钥（支持多个密钥轮询）
    brevo_api_keys = []

    # 优先使用 BREVO_API_KEYS（逗号分隔的多个密钥）
    api_keys_str = os.getenv("BREVO_API_KEYS", "")
    if api_keys_str:
        # 分割并过滤空字符串
        brevo_api_keys = [key.strip() for key in api_keys_str.split(",") if key.strip()]

    # 如果没有配置 BREVO_API_KEYS，则使用单个 BREVO_API_KEY（向后兼容）
    if not brevo_api_keys:
        single_key = os.getenv("BREVO_API_KEY", "")
        if single_key:
            brevo_api_keys = [single_key]

    return Config(
        database_url=database_url,
        feishu_webhook_url=os.getenv("FEISHU_WEBHOOK_URL", ""),
        brevo_api_keys=brevo_api_keys,
        brevo_sender_email=os.getenv("BREVO_SENDER_EMAIL", "noreply@guardssl.info"),
        brevo_sender_name=os.getenv("BREVO_SENDER_NAME", "GuardSSL"),
        brand_name=os.getenv("BRAND_NAME", "Guard SSL"),
        brand_url=os.getenv("BRAND_URL", "https://guardssl.info"),
        dashboard_url=os.getenv("DASHBOARD_URL", "https://guardssl.info/dashboard"),
        ssl_check_timeout=int(os.getenv("SSL_CHECK_TIMEOUT", "10")),
        max_retries=int(os.getenv("MAX_RETRIES", "3")),
        retry_delay=int(os.getenv("RETRY_DELAY", "2")),
        expiring_threshold_days=int(os.getenv("EXPIRING_THRESHOLD_DAYS", "30")),
        # 批处理配置
        batch_size=int(os.getenv("BATCH_SIZE", "10")),
        rate_limit_delay=float(os.getenv("RATE_LIMIT_DELAY", "0.1")),
        max_workers=int(os.getenv("MAX_WORKERS", "10")),
    )
