"""
多语言消息模块
从 JSON 文件加载多语言消息模板
"""
import json
import os
from typing import Optional

# 加载消息模板
_messages_path = os.path.join(os.path.dirname(__file__), "messages.json")
with open(_messages_path, "r", encoding="utf-8") as f:
    MESSAGES = json.load(f)

# 加载邮件 HTML 模板
_email_templates_path = os.path.join(os.path.dirname(__file__), "email_templates.json")
with open(_email_templates_path, "r", encoding="utf-8") as f:
    EMAIL_TEMPLATES = json.load(f)

# 默认语言
DEFAULT_LANGUAGE = "zh-CN"

# 支持的语言列表
SUPPORTED_LANGUAGES = list(MESSAGES.keys())


def get_message(
    status: str,
    field: str,
    language: str = DEFAULT_LANGUAGE,
    **kwargs
) -> str:
    """
    获取多语言消息
    
    Args:
        status: 状态类型 (ssl_expired, ssl_expiring, ssl_error, ssl_valid)
        field: 字段名 (title, message, email_subject, email_body)
        language: 语言代码 (zh-CN, en, ja)
        **kwargs: 模板变量 (domain, days_remaining, error_message)
        
    Returns:
        格式化后的消息字符串
    """
    # 如果语言不支持，回退到默认语言
    if language not in MESSAGES:
        language = DEFAULT_LANGUAGE
    
    # 获取消息模板
    template = MESSAGES.get(language, {}).get(status, {}).get(field, "")
    
    # 如果模板为空，尝试使用默认语言
    if not template and language != DEFAULT_LANGUAGE:
        template = MESSAGES.get(DEFAULT_LANGUAGE, {}).get(status, {}).get(field, "")
    
    # 格式化模板
    if template:
        return template.format(**kwargs)
    
    return ""


def get_status_key(status: str) -> str:
    """
    将 SSL 状态转换为消息键
    
    Args:
        status: SSL 状态 (valid, expiring, expired, error)
        
    Returns:
        消息键 (ssl_valid, ssl_expiring, ssl_expired, ssl_error)
    """
    return f"ssl_{status}"


def translate_error_message(error_code: str, language: str = DEFAULT_LANGUAGE) -> str:
    """
    翻译错误消息代码
    
    错误代码格式: ERROR_CODE 或 ERROR_CODE:详细信息
    
    Args:
        error_code: 错误代码（如 CONNECTION_TIMEOUT, DNS_RESOLUTION_FAILED:xxx）
        language: 语言代码
        
    Returns:
        翻译后的错误消息
    """
    if not error_code:
        return ""
    
    # 如果语言不支持，回退到默认语言
    if language not in MESSAGES:
        language = DEFAULT_LANGUAGE
    
    # 分离错误代码和详细信息
    parts = error_code.split(":", 1)
    code = parts[0]
    detail = parts[1] if len(parts) > 1 else ""
    
    # 获取翻译
    errors = MESSAGES.get(language, {}).get("errors", {})
    translated = errors.get(code, code)
    
    # 如果有详细信息，附加上去
    if detail:
        return f"{translated}: {detail}"
    
    return translated


def get_email_template(
    status: str,
    language: str = DEFAULT_LANGUAGE,
    **kwargs
) -> dict:
    """
    获取邮件 HTML 模板
    
    使用 $variable 语法替换变量，避免与 CSS 中的 {} 冲突
    
    Args:
        status: 状态类型 (ssl_expired, ssl_expiring, ssl_error)
        language: 语言代码 (zh-CN, en, ja)
        **kwargs: 模板变量 (domain, days_remaining, error_message)
        
    Returns:
        包含 subject 和 html 的字典
    """
    from string import Template
    
    # 如果语言不支持，回退到默认语言
    if language not in EMAIL_TEMPLATES:
        language = DEFAULT_LANGUAGE
    
    # 获取模板
    template_data = EMAIL_TEMPLATES.get(language, {}).get(status, {})
    
    # 如果模板为空，尝试使用默认语言
    if not template_data and language != DEFAULT_LANGUAGE:
        template_data = EMAIL_TEMPLATES.get(DEFAULT_LANGUAGE, {}).get(status, {})
    
    if not template_data:
        return {"subject": "", "html": ""}
    
    # 使用 string.Template 进行安全替换（$variable 语法）
    subject_template = Template(template_data.get("subject", ""))
    html_template = Template(template_data.get("html", ""))
    
    return {
        "subject": subject_template.safe_substitute(**kwargs),
        "html": html_template.safe_substitute(**kwargs),
    }
