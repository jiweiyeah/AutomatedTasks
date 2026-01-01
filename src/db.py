"""
数据库操作模块
直接连接 PostgreSQL 数据库进行数据读写
"""
import time
import uuid
import logging
from datetime import datetime, date
from typing import List, Optional, Set
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

from .models import (
    DomainWithUser,
    SSLCheckRecord,
    NotificationChannel,
    NotificationLogRecord,
    SystemMessageRecord,
    TaskLog,
    DomainProgress,
)
from .config import Config

logger = logging.getLogger(__name__)


class DatabaseConnectionError(Exception):
    """数据库连接失败"""
    pass


class DatabaseClient:
    """数据库操作客户端"""
    
    def __init__(self, config: Config):
        """
        初始化数据库客户端
        
        Args:
            config: 应用配置
        """
        self.config = config
        self.connection = None
    
    def connect(self) -> None:
        """
        连接数据库，带重试逻辑
        
        Raises:
            DatabaseConnectionError: 连接失败
        """
        for attempt in range(self.config.max_retries):
            try:
                self.connection = psycopg2.connect(
                    self.config.database_url,
                    cursor_factory=RealDictCursor
                )
                logger.info("数据库连接成功")
                return
            except psycopg2.OperationalError as e:
                if attempt == self.config.max_retries - 1:
                    raise DatabaseConnectionError(
                        f"数据库连接失败，已重试 {self.config.max_retries} 次: {e}"
                    )
                wait_time = self.config.retry_delay * (2 ** attempt)
                logger.warning(f"数据库连接失败，{wait_time} 秒后重试: {e}")
                time.sleep(wait_time)
    
    def close(self) -> None:
        """关闭数据库连接"""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("数据库连接已关闭")
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==================== 域名相关方法 ====================
    
    def get_domains_by_tier(self, tier: str) -> List[DomainWithUser]:
        """
        获取指定订阅等级的活跃域名列表
        
        Args:
            tier: 订阅等级 (free, pro, premium)
            
        Returns:
            域名列表（包含用户信息）
        """
        query = """
            SELECT 
                d.id,
                d.domain,
                d.user_id,
                d.is_active,
                d.notes,
                u.email as user_email,
                u.plan as user_plan
            FROM domains d
            JOIN "user" u ON d.user_id = u.id
            WHERE u.plan = %s AND d.is_active = true
            ORDER BY d.created_at
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (tier,))
            rows = cursor.fetchall()
        
        return [
            DomainWithUser(
                id=row["id"],
                domain=row["domain"],
                user_id=row["user_id"],
                user_email=row["user_email"],
                user_plan=row["user_plan"],
                is_active=row["is_active"],
                notes=row["notes"],
            )
            for row in rows
        ]
    
    def update_domain_status(
        self, domain_id: str, status: str, checked_at: datetime
    ) -> None:
        """
        更新域名检查状态
        
        Args:
            domain_id: 域名 ID
            status: 检查状态
            checked_at: 检查时间
        """
        query = """
            UPDATE domains
            SET last_check_status = %s, last_check_at = %s, updated_at = %s
            WHERE id = %s
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (status, checked_at, datetime.now(), domain_id))
        self.connection.commit()
    
    # ==================== SSL 检查相关方法 ====================
    
    def insert_ssl_check(self, check: SSLCheckRecord) -> str:
        """
        插入 SSL 检查记录
        
        Args:
            check: SSL 检查记录
            
        Returns:
            记录 ID
        """
        query = """
            INSERT INTO ssl_checks (
                id, domain_id, status, is_valid, issuer, valid_from, valid_to,
                days_remaining, protocol, cipher, serial_number, fingerprint,
                fingerprint_sha256, issuer_org, subject_alt_names, bits,
                ext_key_usage, ocsp_uri, ca_issuers_uri, asn1_curve, nist_curve,
                error_message, checked_at,
                security_grade, security_score, has_critical_issues, security_details,
                chain_length, chain_complete, chain_details,
                protocol_secure, cipher_secure, overall_risk, cipher_details
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (
                check.id,
                check.domain_id,
                check.status,
                check.is_valid,
                check.issuer,
                check.valid_from,
                check.valid_to,
                check.days_remaining,
                check.protocol,
                check.cipher,
                check.serial_number,
                check.fingerprint,
                check.fingerprint_sha256,
                check.issuer_org,
                check.subject_alt_names,
                check.bits,
                check.ext_key_usage,
                check.ocsp_uri,
                check.ca_issuers_uri,
                check.asn1_curve,
                check.nist_curve,
                check.error_message,
                check.checked_at,
                # 安全评分相关字段
                check.security_grade,
                check.security_score,
                check.has_critical_issues,
                check.security_details,
                # 证书链相关字段
                check.chain_length,
                check.chain_complete,
                check.chain_details,
                # 加密分析相关字段
                check.protocol_secure,
                check.cipher_secure,
                check.overall_risk,
                check.cipher_details,
            ))
        self.connection.commit()
        return check.id

    # ==================== 通知相关方法 ====================
    
    def get_notification_channels(self, user_id: str) -> List[NotificationChannel]:
        """
        获取用户启用的通知渠道
        
        Args:
            user_id: 用户 ID
            
        Returns:
            启用的通知渠道列表
        """
        query = """
            SELECT id, user_id, channel_type, enabled, encrypted_config, verified
            FROM notification_channels
            WHERE user_id = %s AND enabled = true
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (user_id,))
            rows = cursor.fetchall()
        
        return [
            NotificationChannel(
                id=row["id"],
                user_id=row["user_id"],
                channel_type=row["channel_type"],
                enabled=row["enabled"],
                encrypted_config=row["encrypted_config"],
                verified=row["verified"],
            )
            for row in rows
        ]
    
    def get_user_notification_settings(self, user_id: str) -> dict:
        """
        获取用户的通知设置（语言和频率）
        
        Args:
            user_id: 用户 ID
            
        Returns:
            包含 language 和 frequency 的字典
        """
        query = """
            SELECT language, frequency
            FROM notification_settings
            WHERE user_id = %s
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (user_id,))
            row = cursor.fetchone()
        
        return {
            "language": row.get("language", "zh-CN") if row else "zh-CN",
            "frequency": row.get("frequency", "daily") if row else "daily",
        }
    
    def get_user_language(self, user_id: str) -> str:
        """
        获取用户的通知语言偏好
        
        Args:
            user_id: 用户 ID
            
        Returns:
            语言代码，默认 zh-CN
        """
        settings = self.get_user_notification_settings(user_id)
        return settings["language"]
    

    
    def insert_notification_log(self, log: NotificationLogRecord) -> str:
        """
        插入通知日志
        
        Args:
            log: 通知日志记录
            
        Returns:
            记录 ID
        """
        query = """
            INSERT INTO notification_logs (
                id, channel_id, notification_type, status, sent_at, error_message, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (
                log.id,
                log.channel_id,
                log.notification_type,
                log.status,
                log.sent_at,
                log.error_message,
                log.metadata,
            ))
        self.connection.commit()
        return log.id
    
    def insert_system_message(self, message: SystemMessageRecord) -> str:
        """
        插入系统消息
        
        Args:
            message: 系统消息记录
            
        Returns:
            记录 ID
        """
        query = """
            INSERT INTO system_messages (
                id, user_id, title, message, severity, is_read, metadata, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        created_at = message.created_at or datetime.now()
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (
                message.id,
                message.user_id,
                message.title,
                message.message,
                message.severity,
                message.is_read,
                message.metadata,
                created_at,
            ))
        self.connection.commit()
        return message.id
    
    # ==================== 任务日志相关方法 ====================
    
    def get_task_log(self, task_date: date, tier: str) -> Optional[TaskLog]:
        """
        获取任务执行日志
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            
        Returns:
            任务日志，不存在则返回 None
        """
        query = """
            SELECT id, task_date, tier, status, started_at, completed_at,
                   domains_checked, domains_failed, error_message
            FROM monitor_task_logs
            WHERE task_date::date = %s AND tier = %s
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (task_date, tier))
            row = cursor.fetchone()
        
        if not row:
            return None
        
        return TaskLog(
            id=row["id"],
            task_date=row["task_date"].date() if isinstance(row["task_date"], datetime) else row["task_date"],
            tier=row["tier"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            domains_checked=row["domains_checked"] or 0,
            domains_failed=row["domains_failed"] or 0,
            error_message=row["error_message"],
        )
    
    def upsert_task_log(self, log: TaskLog) -> str:
        """
        创建或更新任务执行日志
        
        Args:
            log: 任务日志
            
        Returns:
            记录 ID
        """
        # 先尝试更新
        update_query = """
            UPDATE monitor_task_logs
            SET status = %s, completed_at = %s, domains_checked = %s,
                domains_failed = %s, error_message = %s, updated_at = %s
            WHERE task_date::date = %s AND tier = %s
            RETURNING id
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(update_query, (
                log.status,
                log.completed_at,
                log.domains_checked,
                log.domains_failed,
                log.error_message,
                datetime.now(),
                log.task_date,
                log.tier,
            ))
            result = cursor.fetchone()
        
        if result:
            self.connection.commit()
            return result["id"]
        
        # 不存在则插入
        insert_query = """
            INSERT INTO monitor_task_logs (
                id, task_date, tier, status, started_at, completed_at,
                domains_checked, domains_failed, error_message, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        now = datetime.now()
        with self.connection.cursor() as cursor:
            cursor.execute(insert_query, (
                log.id,
                log.task_date,
                log.tier,
                log.status,
                log.started_at,
                log.completed_at,
                log.domains_checked,
                log.domains_failed,
                log.error_message,
                now,
                now,
            ))
        self.connection.commit()
        return log.id

    # ==================== 进度追踪相关方法 ====================
    
    def get_domain_progress(
        self, 
        task_date: date, 
        tier: str
    ) -> List[DomainProgress]:
        """
        获取指定任务日期和等级的所有进度记录
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            
        Returns:
            进度记录列表
        """
        query = """
            SELECT id, task_date, tier, domain_id, status, ssl_status,
                   checked_at, notification_sent, error_message,
                   created_at, updated_at
            FROM domain_check_progress
            WHERE task_date = %s AND tier = %s
        """
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, (task_date, tier))
            rows = cursor.fetchall()
        
        return [
            DomainProgress(
                id=row["id"],
                task_date=row["task_date"].date() if isinstance(row["task_date"], datetime) else row["task_date"],
                tier=row["tier"],
                domain_id=row["domain_id"],
                status=row["status"],
                ssl_status=row["ssl_status"],
                checked_at=row["checked_at"],
                notification_sent=row["notification_sent"] or False,
                error_message=row["error_message"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]
    
    def upsert_domain_progress(self, progress: DomainProgress) -> str:
        """
        创建或更新域名进度记录
        
        Args:
            progress: 进度记录
            
        Returns:
            记录 ID
        """
        query = """
            INSERT INTO domain_check_progress (
                id, task_date, tier, domain_id, status, ssl_status,
                checked_at, notification_sent, error_message, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (task_date, tier, domain_id) 
            DO UPDATE SET
                status = EXCLUDED.status,
                ssl_status = EXCLUDED.ssl_status,
                checked_at = EXCLUDED.checked_at,
                notification_sent = EXCLUDED.notification_sent,
                error_message = EXCLUDED.error_message,
                updated_at = EXCLUDED.updated_at
            RETURNING id
        """
        
        now = datetime.now()
        with self.connection.cursor() as cursor:
            cursor.execute(query, (
                progress.id,
                progress.task_date,
                progress.tier,
                progress.domain_id,
                progress.status,
                progress.ssl_status,
                progress.checked_at,
                progress.notification_sent,
                progress.error_message,
                progress.created_at or now,
                progress.updated_at or now,
            ))
            result = cursor.fetchone()
        
        self.connection.commit()
        return result["id"] if result else progress.id
    
    def batch_upsert_domain_progress(
        self, 
        progress_list: List[DomainProgress]
    ) -> int:
        """
        批量创建或更新域名进度记录
        
        Args:
            progress_list: 进度记录列表
            
        Returns:
            更新的记录数
        """
        if not progress_list:
            return 0
        
        query = """
            INSERT INTO domain_check_progress (
                id, task_date, tier, domain_id, status, ssl_status,
                checked_at, notification_sent, error_message, created_at, updated_at
            ) VALUES %s
            ON CONFLICT (task_date, tier, domain_id) 
            DO UPDATE SET
                status = EXCLUDED.status,
                ssl_status = EXCLUDED.ssl_status,
                checked_at = EXCLUDED.checked_at,
                notification_sent = EXCLUDED.notification_sent,
                error_message = EXCLUDED.error_message,
                updated_at = EXCLUDED.updated_at
        """
        
        now = datetime.now()
        values = [
            (
                p.id,
                p.task_date,
                p.tier,
                p.domain_id,
                p.status,
                p.ssl_status,
                p.checked_at,
                p.notification_sent,
                p.error_message,
                p.created_at or now,
                p.updated_at or now,
            )
            for p in progress_list
        ]
        
        with self.connection.cursor() as cursor:
            execute_values(cursor, query, values)
            count = cursor.rowcount
        
        self.connection.commit()
        return count

    
    def batch_insert_ssl_checks(self, checks: List[SSLCheckRecord]) -> int:
        """
        批量插入 SSL 检查记录
        
        Args:
            checks: SSL 检查记录列表
            
        Returns:
            插入的记录数
        """
        if not checks:
            return 0
        
        query = """
            INSERT INTO ssl_checks (
                id, domain_id, status, is_valid, issuer, valid_from, valid_to,
                days_remaining, protocol, cipher, serial_number, fingerprint,
                fingerprint_sha256, issuer_org, subject_alt_names, bits,
                ext_key_usage, ocsp_uri, ca_issuers_uri, asn1_curve, nist_curve,
                error_message, checked_at,
                security_grade, security_score, has_critical_issues, security_details,
                chain_length, chain_complete, chain_details,
                protocol_secure, cipher_secure, overall_risk, cipher_details
            ) VALUES %s
        """
        
        values = [
            (
                c.id,
                c.domain_id,
                c.status,
                c.is_valid,
                c.issuer,
                c.valid_from,
                c.valid_to,
                c.days_remaining,
                c.protocol,
                c.cipher,
                c.serial_number,
                c.fingerprint,
                c.fingerprint_sha256,
                c.issuer_org,
                c.subject_alt_names,
                c.bits,
                c.ext_key_usage,
                c.ocsp_uri,
                c.ca_issuers_uri,
                c.asn1_curve,
                c.nist_curve,
                c.error_message,
                c.checked_at,
                # 安全评分相关字段
                c.security_grade,
                c.security_score,
                c.has_critical_issues,
                c.security_details,
                # 证书链相关字段
                c.chain_length,
                c.chain_complete,
                c.chain_details,
                # 加密分析相关字段
                c.protocol_secure,
                c.cipher_secure,
                c.overall_risk,
                c.cipher_details,
            )
            for c in checks
        ]
        
        with self.connection.cursor() as cursor:
            execute_values(cursor, query, values)
            count = cursor.rowcount
        
        self.connection.commit()
        return count

    
    def get_domains_to_check(
        self, 
        tier: str, 
        exclude_domain_ids: Optional[Set[str]] = None
    ) -> List[DomainWithUser]:
        """
        获取待检测的域名列表（排除已完成的）
        
        Args:
            tier: 订阅等级
            exclude_domain_ids: 要排除的域名 ID 集合
            
        Returns:
            待检测的域名列表
        """
        # 基础查询
        base_query = """
            SELECT 
                d.id,
                d.domain,
                d.user_id,
                d.is_active,
                d.notes,
                u.email as user_email,
                u.plan as user_plan
            FROM domains d
            JOIN "user" u ON d.user_id = u.id
            WHERE u.plan = %s AND d.is_active = true
        """
        
        # 如果有排除列表，添加 NOT IN 条件
        if exclude_domain_ids:
            # 将 UUID 集合转换为元组
            exclude_tuple = tuple(exclude_domain_ids)
            query = base_query + " AND d.id NOT IN %s ORDER BY d.created_at"
            params = (tier, exclude_tuple)
        else:
            query = base_query + " ORDER BY d.created_at"
            params = (tier,)
        
        with self.connection.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        return [
            DomainWithUser(
                id=row["id"],
                domain=row["domain"],
                user_id=row["user_id"],
                user_email=row["user_email"],
                user_plan=row["user_plan"],
                is_active=row["is_active"],
                notes=row["notes"],
            )
            for row in rows
        ]
