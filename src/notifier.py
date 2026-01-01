"""
通知发送模块
支持多渠道通知：Email、Slack、Discord、Telegram、飞书
支持多语言消息模板
"""
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import requests

from .config import Config
from .i18n import (
    get_message, get_status_key, get_email_template, 
    translate_error_message, DEFAULT_LANGUAGE
)

logger = logging.getLogger(__name__)


# 渠道类型常量
class ChannelType:
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    FEISHU = "feishu"
    SYSTEM_MESSAGE = "system_message"


@dataclass
class NotificationPayload:
    """通知内容"""
    domain: str
    status: str
    days_remaining: Optional[int] = None
    error_message: Optional[str] = None
    
    def to_message(self, language: str = DEFAULT_LANGUAGE) -> str:
        """生成通知消息文本"""
        status_key = get_status_key(self.status)
        # 翻译错误消息
        translated_error = translate_error_message(self.error_message or "", language)
        return get_message(
            status_key, "message", language,
            domain=self.domain,
            days_remaining=self.days_remaining or 0,
            error_message=translated_error
        )
    
    def to_title(self, language: str = DEFAULT_LANGUAGE) -> str:
        """生成通知标题"""
        status_key = get_status_key(self.status)
        return get_message(
            status_key, "title", language,
            domain=self.domain,
            days_remaining=self.days_remaining or 0,
            error_message=self.error_message or ""
        )
    
    def to_email_subject(self, language: str = DEFAULT_LANGUAGE) -> str:
        """生成邮件主题"""
        status_key = get_status_key(self.status)
        return get_message(
            status_key, "email_subject", language,
            domain=self.domain,
            days_remaining=self.days_remaining or 0,
            error_message=self.error_message or ""
        )
    
    def to_email_body(self, language: str = DEFAULT_LANGUAGE) -> str:
        """生成邮件正文"""
        status_key = get_status_key(self.status)
        # 翻译错误消息
        translated_error = translate_error_message(self.error_message or "", language)
        return get_message(
            status_key, "email_body", language,
            domain=self.domain,
            days_remaining=self.days_remaining or 0,
            error_message=translated_error
        )


@dataclass
class WorkflowSummary:
    """工作流执行汇总"""
    tier: str
    task_date: str
    domains_total: int
    domains_checked: int
    domains_failed: int
    domains_expiring: int
    domains_expired: int
    domains_error: int
    duration_seconds: float
    domains_skipped: int = 0  # 断点续作跳过的域名数
    
    def to_feishu_message(self) -> Dict[str, Any]:
        """生成飞书卡片消息"""
        # 根据结果确定卡片颜色
        if self.domains_failed > 0 or self.domains_expired > 0:
            template = "red"
            status_emoji = "❌"
        elif self.domains_expiring > 0 or self.domains_error > 0:
            template = "orange"
            status_emoji = "⚠️"
        else:
            template = "green"
            status_emoji = "✅"
        
        # 计算本次新检测的域名数
        domains_new_checked = self.domains_checked - self.domains_skipped
        
        # 构建详情内容
        details = [
            f"📅 任务日期: {self.task_date}",
            f"🏷️ 订阅等级: {self.tier.upper()}",
            f"📊 域名总数: {self.domains_total}",
            f"🔄 本次检测: {domains_new_checked}",
            f"⏭️ 跳过(已检测): {self.domains_skipped}",
            f"✅ 检查成功: {self.domains_checked - self.domains_failed}",
            f"❌ 检查失败: {self.domains_failed}",
            f"⚠️ 即将过期: {self.domains_expiring}",
            f"🚨 已过期: {self.domains_expired}",
            f"💥 检查错误: {self.domains_error}",
            f"⏱️ 执行耗时: {self.duration_seconds:.1f} 秒",
        ]
        
        return {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": f"{status_emoji} GuardSSL 监控任务完成 - {self.tier.upper()}"
                    },
                    "template": template
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "plain_text",
                            "content": "\n".join(details)
                        }
                    }
                ]
            }
        }


class NotificationError(Exception):
    """通知发送失败"""
    def __init__(self, channel_type: str, message: str):
        self.channel_type = channel_type
        self.message = message
        super().__init__(f"通知发送失败 [{channel_type}]: {message}")


class Notifier:
    """通知发送器"""
    
    def __init__(self, config: Config):
        """
        初始化通知器
        
        Args:
            config: 应用配置
        """
        self.config = config
    
    def send_workflow_summary(self, summary: WorkflowSummary) -> bool:
        """
        发送工作流执行汇总到管理员飞书
        
        Args:
            summary: 工作流汇总信息
            
        Returns:
            是否发送成功
        """
        if not self.config.feishu_webhook_url:
            logger.warning("飞书 Webhook URL 未配置，跳过工作流汇总通知")
            return False
        
        try:
            message = summary.to_feishu_message()
            response = requests.post(
                self.config.feishu_webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("code") == 0:
                    logger.info("工作流汇总通知发送成功")
                    return True
                else:
                    logger.error(f"飞书 API 错误: {result.get('msg')}")
                    return False
            else:
                logger.error(f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            logger.error(f"发送工作流汇总通知失败: {e}")
            return False
    
    def send_to_channel(
        self,
        channel_type: str,
        channel_config: Dict[str, Any],
        payload: NotificationPayload,
        language: str = DEFAULT_LANGUAGE
    ) -> bool:
        """
        发送通知到指定渠道
        
        Args:
            channel_type: 渠道类型
            channel_config: 渠道配置（从数据库读取的 encryptedConfig）
            payload: 通知内容
            language: 用户语言偏好
            
        Returns:
            是否发送成功
        """
        # system_message 渠道不需要外部发送，通过 insert_system_message 处理
        if channel_type == ChannelType.SYSTEM_MESSAGE:
            logger.debug("system_message 渠道通过数据库处理，跳过外部发送")
            return True
        
        try:
            if channel_type == ChannelType.EMAIL:
                return self._send_email(channel_config, payload, language)
            elif channel_type == ChannelType.SLACK:
                return self._send_slack(channel_config, payload, language)
            elif channel_type == ChannelType.DISCORD:
                return self._send_discord(channel_config, payload, language)
            elif channel_type == ChannelType.TELEGRAM:
                return self._send_telegram(channel_config, payload, language)
            elif channel_type == ChannelType.FEISHU:
                return self._send_feishu(channel_config, payload, language)
            else:
                logger.warning(f"不支持的渠道类型: {channel_type}")
                return False
        except NotificationError as e:
            logger.error(str(e))
            return False
        except Exception as e:
            logger.error(f"发送通知失败 [{channel_type}]: {e}")
            return False
    
    def send_to_feishu(self, payload: NotificationPayload, language: str = DEFAULT_LANGUAGE) -> bool:
        """
        发送通知到管理员飞书（用于告警）
        
        Args:
            payload: 通知内容
            language: 语言
            
        Returns:
            是否发送成功
        """
        if not self.config.feishu_webhook_url:
            logger.warning("飞书 Webhook URL 未配置，跳过通知")
            return False
        
        try:
            return self._send_feishu(
                {"webhookUrl": self.config.feishu_webhook_url}, 
                payload, 
                language
            )
        except Exception as e:
            logger.error(f"发送飞书通知失败: {e}")
            return False

    def _send_email(
        self, config: Dict[str, Any], payload: NotificationPayload, language: str
    ) -> bool:
        """
        发送邮件通知（使用 Brevo API）
        
        配置格式: { type: "email", recipients: ["email@example.com"] }
        """
        recipients = config.get("recipients", [])
        if not recipients:
            raise NotificationError(ChannelType.EMAIL, "收件人邮箱未配置")
        
        # 检查 Brevo API 配置
        if not self.config.brevo_api_key:
            raise NotificationError(ChannelType.EMAIL, "BREVO_API_KEY 未配置")
        
        # 获取 HTML 邮件模板（翻译错误消息，传入品牌配置）
        status_key = get_status_key(payload.status)
        translated_error = translate_error_message(payload.error_message or "", language)
        email_template = get_email_template(
            status_key, language,
            domain=payload.domain,
            days_remaining=payload.days_remaining or 0,
            error_message=translated_error,
            brand_name=self.config.brand_name,
            brand_url=self.config.brand_url,
            dashboard_url=self.config.dashboard_url
        )
        
        # 构建收件人列表
        to_list = [
            {"email": email, "name": email.split("@")[0]}
            for email in (recipients if isinstance(recipients, list) else [recipients])
        ]
        
        # 构建请求体
        request_body = {
            "sender": {
                "name": self.config.brevo_sender_name,
                "email": self.config.brevo_sender_email,
            },
            "to": to_list,
            "subject": email_template["subject"] or payload.to_email_subject(language),
            "htmlContent": email_template["html"] or "",
            "textContent": payload.to_email_body(language),
        }
        
        # 调用 Brevo API
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": self.config.brevo_api_key,
                "content-type": "application/json",
            },
            json=request_body,
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            result = response.json()
            logger.info(f"邮件发送成功，Message ID: {result.get('messageId')}")
            return True
        else:
            raise NotificationError(
                ChannelType.EMAIL,
                f"Brevo API 错误: {response.status_code} - {response.text}"
            )
    
    def _send_slack(
        self, config: Dict[str, Any], payload: NotificationPayload, language: str
    ) -> bool:
        """发送 Slack 通知"""
        webhook_url = config.get("webhookUrl")
        if not webhook_url:
            raise NotificationError(ChannelType.SLACK, "Webhook URL 未配置")
        
        message = {
            "text": payload.to_title(language),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": payload.to_message(language)
                    }
                }
            ]
        }
        
        response = requests.post(webhook_url, json=message, timeout=10)
        
        if response.status_code == 200:
            logger.info("Slack 通知发送成功")
            return True
        else:
            raise NotificationError(
                ChannelType.SLACK, 
                f"HTTP {response.status_code}: {response.text}"
            )
    
    def _send_discord(
        self, config: Dict[str, Any], payload: NotificationPayload, language: str
    ) -> bool:
        """发送 Discord 通知"""
        webhook_url = config.get("webhookUrl")
        if not webhook_url:
            raise NotificationError(ChannelType.DISCORD, "Webhook URL 未配置")
        
        # 根据状态设置颜色
        color = 16711680 if payload.status in ["expired", "error"] else 16776960
        
        message = {
            "embeds": [
                {
                    "title": payload.to_title(language),
                    "description": payload.to_message(language),
                    "color": color
                }
            ]
        }
        
        response = requests.post(webhook_url, json=message, timeout=10)
        
        if response.status_code in [200, 204]:
            logger.info("Discord 通知发送成功")
            return True
        else:
            raise NotificationError(
                ChannelType.DISCORD,
                f"HTTP {response.status_code}: {response.text}"
            )
    
    def _send_telegram(
        self, config: Dict[str, Any], payload: NotificationPayload, language: str
    ) -> bool:
        """发送 Telegram 通知"""
        bot_token = config.get("botToken")
        chat_id = config.get("chatId")
        
        if not bot_token or not chat_id:
            raise NotificationError(ChannelType.TELEGRAM, "Bot Token 或 Chat ID 未配置")
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        message = {
            "chat_id": chat_id,
            "text": f"*{payload.to_title(language)}*\n\n{payload.to_message(language)}",
            "parse_mode": "Markdown"
        }
        
        response = requests.post(url, json=message, timeout=10)
        
        if response.status_code == 200:
            logger.info("Telegram 通知发送成功")
            return True
        else:
            raise NotificationError(
                ChannelType.TELEGRAM,
                f"HTTP {response.status_code}: {response.text}"
            )
    
    def _send_feishu(
        self, config: Dict[str, Any], payload: NotificationPayload, language: str
    ) -> bool:
        """发送飞书通知"""
        webhook_url = config.get("webhookUrl")
        if not webhook_url:
            raise NotificationError(ChannelType.FEISHU, "Webhook URL 未配置")
        
        # 根据状态设置卡片颜色
        template = "red" if payload.status in ["expired", "error"] else "orange"
        
        message = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": payload.to_title(language)
                    },
                    "template": template
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "plain_text",
                            "content": payload.to_message(language)
                        }
                    }
                ]
            }
        }
        
        response = requests.post(webhook_url, json=message, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == 0:
                logger.info("飞书通知发送成功")
                return True
            else:
                raise NotificationError(
                    ChannelType.FEISHU,
                    f"飞书 API 错误: {result.get('msg')}"
                )
        else:
            raise NotificationError(
                ChannelType.FEISHU,
                f"HTTP {response.status_code}: {response.text}"
            )
