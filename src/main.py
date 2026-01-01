"""
SSL Monitor Worker 主入口
GitHub Action 定时任务 SSL 证书监控服务
支持断点续作和并行批量处理
"""
import argparse
import logging
import sys
import uuid
import json
import time
from datetime import datetime, date, timezone
from typing import List, Dict, Any, Optional

from .config import load_config, Config, SubscriptionTier, SSLStatus
from .db import DatabaseClient, DatabaseConnectionError
from .ssl_checker import SSLChecker, SSLCheckResult, ExtendedSSLCheckResult
from .notifier import (
    Notifier, NotificationPayload, NotificationError, 
    WorkflowSummary, ChannelType
)
from .task_manager import TaskManager
from .progress_tracker import ProgressTracker
from .batch_processor import BatchProcessor, BatchConfig, BatchResult
from .models import (
    DomainWithUser,
    SSLCheckRecord,
    NotificationLogRecord,
    SystemMessageRecord,
    DomainCheckStatus,
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="SSL Monitor Worker - SSL 证书定时监控服务"
    )
    parser.add_argument(
        "--tier",
        type=str,
        required=True,
        choices=SubscriptionTier.ALL,
        help="订阅等级: premium, pro, free"
    )
    parser.add_argument(
        "--date",
        type=str,
        default=None,
        help="任务日期 (YYYY-MM-DD)，默认为今天"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="试运行模式，不实际发送通知"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="批处理大小，默认使用配置值"
    )
    return parser.parse_args()


def should_send_notification(
    status: str,
    days_remaining: int,
    frequency: str
) -> bool:
    """
    根据用户设置的通知频率判断是否应该发送通知
    
    frequency 含义是"证书过期前多少天开始通知"：
    - daily: 每天都通知（Premium 专属）
    - 3_days_before: 只有剩余天数 ≤ 3 天才通知
    - 7_days_before: 只有剩余天数 ≤ 7 天才通知
    - 30_days_before: 只有剩余天数 ≤ 30 天才通知
    """
    # 已过期或检查错误：始终通知
    if status in [SSLStatus.EXPIRED, SSLStatus.ERROR]:
        return True
    
    # 对于 expiring 状态，根据用户设置的频率判断
    if status == SSLStatus.EXPIRING:
        if frequency == "daily":
            return True
        if frequency == "3_days_before":
            return days_remaining is not None and days_remaining <= 3
        if frequency == "7_days_before":
            return days_remaining is not None and days_remaining <= 7
        if frequency == "30_days_before":
            return days_remaining is not None and days_remaining <= 30
        # 未知频率，默认使用 30 天
        return days_remaining is not None and days_remaining <= 30
    
    return False


def serialize_chain_info(result: ExtendedSSLCheckResult) -> Optional[str]:
    """
    序列化证书链信息为 JSON 字符串（chain_details 字段）
    格式与 Next.js 前端 SSLChainVisualization 组件期望的格式一致
    
    Args:
        result: 扩展的 SSL 检查结果
        
    Returns:
        JSON 字符串或 None
    """
    if not result.chain_info:
        return None
    
    chain_info = result.chain_info
    
    # 将 subject/issuer 对象转换为字符串（优先使用 CN，其次 O）
    def subject_to_string(subj) -> str:
        if subj.CN:
            return subj.CN
        if subj.O:
            return subj.O
        if subj.OU:
            return subj.OU
        return "Unknown"
    
    # 判断是否即将过期（30天内）
    def is_expiring_soon(days_remaining: int) -> bool:
        return 0 <= days_remaining <= 30
    
    # 构建证书数组，格式与前端 ChainCertificate 接口一致
    certificates = []
    for cert in chain_info.chain:
        certificates.append({
            "type": cert.type,
            "subject": subject_to_string(cert.subject),
            "issuer": subject_to_string(cert.issuer),
            "validFrom": cert.valid_from,
            "validTo": cert.valid_to,
            "daysRemaining": cert.days_remaining,
            "isExpired": cert.days_remaining < 0,
            "isExpiringSoon": is_expiring_soon(cert.days_remaining),
            # 额外字段（可选，用于详情展示）
            "serialNumber": cert.serial_number,
            "signatureAlgorithm": cert.signature_algorithm,
            "publicKeyAlgorithm": cert.public_key_algorithm,
            "keyBits": cert.key_bits,
            "isSelfSigned": cert.is_self_signed,
            "fingerprint256": cert.fingerprint_sha256,
        })
    
    data = {
        "certificates": certificates,
        "earliestExpiry": None,
    }
    
    # 添加推断的根证书信息
    if chain_info.inferred_root:
        data["inferredRoot"] = {
            "name": chain_info.inferred_root.name,
            "organization": chain_info.inferred_root.organization,
            "trusted": chain_info.inferred_root.trusted,
        }
    
    # 添加最早过期信息（从链验证结果获取）
    if result.chain_validation:
        # 找到最早过期的证书名称
        earliest_cert_name = "Unknown"
        if result.chain_validation.earliest_expiring_index >= 0 and certificates:
            idx = result.chain_validation.earliest_expiring_index
            if idx < len(certificates):
                earliest_cert_name = certificates[idx]["subject"]
        
        data["earliestExpiry"] = {
            "certificate": earliest_cert_name,
            "date": result.chain_validation.earliest_expiry_date,
            "daysRemaining": result.chain_validation.earliest_expiry_days,
        }
    
    return json.dumps(data)


def serialize_security_details(result: ExtendedSSLCheckResult) -> Optional[str]:
    """
    序列化安全评分详情为 JSON 字符串（security_details 字段）
    
    Args:
        result: 扩展的 SSL 检查结果
        
    Returns:
        JSON 字符串或 None
    """
    if not result.security_score:
        return None
    
    score = result.security_score
    
    # 从 breakdown 列表构建分类分数字典
    breakdown_dict = {}
    for item in score.breakdown:
        breakdown_dict[item.category] = {
            "score": item.score,
            "weight": item.weight,
            "weightedScore": item.weighted_score,
            "deductions": item.deductions,
        }
    
    data = {
        "breakdown": breakdown_dict,
        "recommendations": score.recommendations,
    }
    
    return json.dumps(data)


def serialize_cipher_details(result: ExtendedSSLCheckResult) -> Optional[str]:
    """
    序列化加密分析详情为 JSON 字符串（cipher_details 字段）
    
    Args:
        result: 扩展的 SSL 检查结果
        
    Returns:
        JSON 字符串或 None
    """
    if not result.cipher_security:
        return None
    
    cipher = result.cipher_security
    data = {
        "issues": [
            {
                "type": issue.type,
                "severity": issue.risk_level,
                "description": issue.description,
                "recommendation": issue.recommendation,
            }
            for issue in cipher.issues
        ] if cipher.issues else [],
        "protocol": {
            "name": cipher.protocol.version,
            "secure": cipher.protocol.is_secure,
            "riskLevel": cipher.protocol.risk_level,
        },
        "cipher": {
            "name": cipher.cipher_suite,
            "secure": cipher.cipher_secure,
        },
    }
    
    return json.dumps(data)



def send_user_notifications(
    domain: DomainWithUser,
    result: SSLCheckResult,
    db: DatabaseClient,
    notifier: Notifier,
    progress_tracker: ProgressTracker,
    dry_run: bool = False
) -> bool:
    """
    根据用户订阅的渠道发送通知（带去重保护）
    
    Args:
        domain: 域名信息
        result: SSL 检查结果
        db: 数据库客户端
        notifier: 通知器
        progress_tracker: 进度追踪器
        dry_run: 是否试运行
        
    Returns:
        是否发送了通知
    """
    # 检查是否已发送通知（去重保护）
    if progress_tracker.is_notification_sent(domain.id):
        logger.debug(f"域名 {domain.domain} 已发送过通知，跳过")
        return False
    
    # 获取用户通知设置（语言和频率）
    settings = db.get_user_notification_settings(domain.user_id)
    language = settings["language"]
    frequency = settings["frequency"]
    
    # 根据频率判断是否应该发送通知
    if not should_send_notification(result.status, result.days_remaining, frequency):
        logger.info(
            f"用户 {domain.user_id} 的域名 {domain.domain} 不满足通知条件 "
            f"(剩余 {result.days_remaining} 天, 设置: {frequency})，跳过发送"
        )
        return False
    
    # 创建通知内容
    payload = NotificationPayload(
        domain=domain.domain,
        status=result.status,
        days_remaining=result.days_remaining,
        error_message=result.error_message,
    )
    
    # 获取用户启用的通知渠道
    channels = db.get_notification_channels(domain.user_id)
    
    if not channels:
        logger.info(f"用户 {domain.user_id} 没有启用任何通知渠道")
        return False
    
    notification_sent = False
    
    # 向每个渠道发送通知
    for channel in channels:
        if dry_run:
            logger.info(f"[试运行] 跳过发送 {channel.channel_type} 通知: {domain.domain}")
            notification_sent = True
            continue
        
        try:
            # 解析渠道配置
            channel_config = {}
            if channel.encrypted_config:
                channel_config = json.loads(channel.encrypted_config)
            
            # 发送通知
            success = notifier.send_to_channel(
                channel.channel_type,
                channel_config,
                payload,
                language
            )
            
            if success:
                notification_sent = True
            
            # 记录通知日志
            log_record = NotificationLogRecord(
                id=str(uuid.uuid4()),
                channel_id=channel.id,
                notification_type=f"ssl_{result.status}",
                status="success" if success else "failed",
                sent_at=datetime.now(),
                error_message=None if success else "发送失败",
                metadata=json.dumps({
                    "domain": domain.domain,
                    "status": result.status,
                    "days_remaining": result.days_remaining,
                    "language": language,
                }),
            )
            db.insert_notification_log(log_record)
            
        except Exception as e:
            logger.error(f"发送 {channel.channel_type} 通知失败: {e}")
            log_record = NotificationLogRecord(
                id=str(uuid.uuid4()),
                channel_id=channel.id,
                notification_type=f"ssl_{result.status}",
                status="failed",
                sent_at=datetime.now(),
                error_message=str(e),
                metadata=json.dumps({
                    "domain": domain.domain,
                    "status": result.status,
                }),
            )
            db.insert_notification_log(log_record)
    
    # 创建系统消息（站内通知）
    if not dry_run and notification_sent:
        severity = "error" if result.status in [SSLStatus.EXPIRED, SSLStatus.ERROR] else "warning"
        system_message = SystemMessageRecord(
            id=str(uuid.uuid4()),
            user_id=domain.user_id,
            title=payload.to_title(language),
            message=payload.to_message(language),
            severity=severity,
            metadata=json.dumps({
                "domain": domain.domain,
                "status": result.status,
                "days_remaining": result.days_remaining,
            }),
        )
        db.insert_system_message(system_message)
    
    # 标记已发送通知（立即更新，防止重复）
    if notification_sent:
        progress_tracker.mark_notification_sent(domain.id)
    
    return notification_sent



def create_domain_processor(
    ssl_checker: SSLChecker,
    db: DatabaseClient,
    notifier: Notifier,
    progress_tracker: ProgressTracker,
    config: Config,
    dry_run: bool = False
):
    """
    创建域名处理函数（用于批处理）
    
    返回一个闭包函数，用于处理单个域名
    """
    def process_single_domain(domain: DomainWithUser) -> BatchResult:
        """处理单个域名的 SSL 检查"""
        logger.info(f"检查域名: {domain.domain}")
        
        try:
            # 标记为检测中
            progress_tracker.mark_checking(domain.id)
            
            # 执行扩展 SSL 检查（包含证书链验证）
            result = ssl_checker.check_extended(domain.domain)
            now_utc = datetime.now(timezone.utc)
            
            # 序列化证书链相关信息
            chain_details_json = serialize_chain_info(result)
            security_details_json = serialize_security_details(result)
            cipher_details_json = serialize_cipher_details(result)
            
            # 获取安全评分信息
            security_grade = None
            security_score = None
            has_critical_issues = None
            if result.security_score:
                security_grade = result.security_score.grade
                security_score = result.security_score.numeric_score
                has_critical_issues = result.security_score.has_critical_issues
            
            # 获取证书链信息
            chain_length = None
            chain_complete = None
            if result.chain_info:
                chain_length = result.chain_info.chain_length
                chain_complete = result.chain_info.is_complete
            
            # 获取加密分析信息
            protocol_secure = None
            cipher_secure = None
            overall_risk = None
            if result.cipher_security:
                # 协议安全性从 protocol.is_secure 获取
                protocol_secure = result.cipher_security.protocol.is_secure
                cipher_secure = result.cipher_security.cipher_secure
                overall_risk = result.cipher_security.overall_risk
            
            # 创建检查记录
            check_record = SSLCheckRecord(
                id=str(uuid.uuid4()),
                domain_id=domain.id,
                status=result.status,
                is_valid=result.is_valid,
                checked_at=now_utc,
                issuer=result.issuer,
                valid_from=result.valid_from,
                valid_to=result.valid_to,
                days_remaining=result.days_remaining,
                protocol=result.protocol,
                cipher=result.cipher,
                serial_number=result.serial_number,
                fingerprint=result.fingerprint,
                fingerprint_sha256=result.fingerprint_sha256,
                issuer_org=result.issuer_org,
                subject_alt_names=result.subject_alt_names,
                bits=result.bits,
                ext_key_usage=result.ext_key_usage,
                ocsp_uri=result.ocsp_uri,
                ca_issuers_uri=result.ca_issuers_uri,
                asn1_curve=result.asn1_curve,
                nist_curve=result.nist_curve,
                error_message=result.error_message,
                # 安全评分相关字段
                security_grade=security_grade,
                security_score=security_score,
                has_critical_issues=has_critical_issues,
                security_details=security_details_json,
                # 证书链相关字段
                chain_length=chain_length,
                chain_complete=chain_complete,
                chain_details=chain_details_json,
                # 加密分析相关字段
                protocol_secure=protocol_secure,
                cipher_secure=cipher_secure,
                overall_risk=overall_risk,
                cipher_details=cipher_details_json,
            )
            
            # 保存检查记录
            db.insert_ssl_check(check_record)
            
            # 更新域名状态
            db.update_domain_status(domain.id, result.status, now_utc)
            
            # 标记检测完成
            progress_tracker.mark_completed(domain.id, result.status, now_utc)
            
            # 日志输出安全评分
            grade_info = f", 安全评级: {security_grade}" if security_grade else ""
            logger.info(
                f"域名 {domain.domain} 检查完成: {result.status} "
                f"(剩余 {result.days_remaining} 天{grade_info})"
            )
            
            # 如果有问题，发送通知
            if result.status in [SSLStatus.EXPIRING, SSLStatus.EXPIRED, SSLStatus.ERROR]:
                send_user_notifications(
                    domain, result, db, notifier, progress_tracker, dry_run
                )
            
            return BatchResult(
                item_id=domain.id,
                success=True,
                result={
                    "status": result.status,
                    "domain": domain.domain,
                    "days_remaining": result.days_remaining,
                    "security_grade": security_grade,
                }
            )
            
        except Exception as e:
            logger.error(f"处理域名 {domain.domain} 失败: {e}")
            
            # 标记检测失败
            progress_tracker.mark_failed(domain.id, str(e))
            
            # 尝试更新域名状态
            try:
                db.update_domain_status(domain.id, SSLStatus.ERROR, datetime.now(timezone.utc))
            except Exception:
                pass
            
            return BatchResult(
                item_id=domain.id,
                success=False,
                error=str(e),
                result={"status": SSLStatus.ERROR, "domain": domain.domain}
            )
    
    return process_single_domain



def run_monitor(
    tier: str, 
    task_date: date, 
    config: Config, 
    dry_run: bool = False,
    batch_size: int = None
) -> None:
    """
    运行监控任务（支持断点续作和并行处理）
    
    Args:
        tier: 订阅等级
        task_date: 任务日期
        config: 应用配置
        dry_run: 是否试运行
        batch_size: 批处理大小
    """
    logger.info(f"开始 {tier} 等级监控任务: {task_date}")
    start_time = time.time()
    
    with DatabaseClient(config) as db:
        task_manager = TaskManager(db)
        progress_tracker = ProgressTracker(db, task_date, tier)
        ssl_checker = SSLChecker(
            timeout=config.ssl_check_timeout,
            expiring_threshold=config.expiring_threshold_days
        )
        notifier = Notifier(config)
        
        # 配置批处理器
        batch_config = BatchConfig(
            batch_size=batch_size or config.batch_size,
            rate_limit_delay=config.rate_limit_delay,
            max_workers=config.max_workers,
        )
        batch_processor = BatchProcessor(batch_config)
        
        # 检查任务是否应该执行
        if not task_manager.should_run(task_date, tier):
            return
        
        # 开始任务
        task_manager.start_task(task_date, tier)
        
        # 统计变量
        domains_total = 0
        domains_checked = 0
        domains_failed = 0
        domains_skipped = 0  # 断点续作跳过的域名
        domains_expiring = 0
        domains_expired = 0
        domains_error = 0
        summary = None
        
        try:
            # 加载现有进度（断点续作）
            progress_tracker.load_existing_progress()
            completed_ids = progress_tracker.get_completed_domain_ids()
            
            # 获取所有域名
            all_domains = db.get_domains_by_tier(tier)
            domains_total = len(all_domains)
            
            # 过滤已完成的域名
            domains_to_check = [d for d in all_domains if d.id not in completed_ids]
            domains_skipped = len(completed_ids)
            
            # 记录恢复信息
            progress_tracker.log_resume_info(domains_total)
            
            if domains_to_check:
                logger.info(f"待检测域名: {len(domains_to_check)} 个")
                
                # 创建处理函数
                process_func = create_domain_processor(
                    ssl_checker, db, notifier, progress_tracker, config, dry_run
                )
                
                # 批量并行处理
                summary = batch_processor.process_all(
                    domains_to_check,
                    process_func
                )
                
                # 统计结果
                if summary:
                    domains_checked = domains_skipped + summary.total
                    domains_failed = summary.failed
                    
                    for result in summary.results:
                        if result.success and result.result:
                            status = result.result.get("status")
                            if status == SSLStatus.EXPIRING:
                                domains_expiring += 1
                            elif status == SSLStatus.EXPIRED:
                                domains_expired += 1
                            elif status == SSLStatus.ERROR:
                                domains_error += 1
                        elif not result.success:
                            domains_error += 1
                else:
                    domains_checked = domains_skipped
                    domains_failed = 0
            else:
                logger.info(f"所有 {domains_total} 个域名已检测完成，无需处理")
                domains_checked = domains_skipped
            
            # 完成任务
            task_manager.complete_task(task_date, tier, domains_checked, domains_failed)
            
            # 计算执行时间
            duration = time.time() - start_time
            
            # 发送工作流汇总通知
            if not dry_run:
                workflow_summary = WorkflowSummary(
                    tier=tier,
                    task_date=str(task_date),
                    domains_total=domains_total,
                    domains_checked=domains_checked,
                    domains_failed=domains_failed,
                    domains_expiring=domains_expiring,
                    domains_expired=domains_expired,
                    domains_error=domains_error,
                    duration_seconds=duration,
                    domains_skipped=domains_skipped,  # 新增字段
                )
                notifier.send_workflow_summary(workflow_summary)
            else:
                logger.info(f"[试运行] 跳过发送工作流汇总通知")
            
            # 日志输出
            batch_count = summary.total if summary else 0
            logger.info(
                f"任务完成: 总计 {domains_total}, 本次检测 {batch_count}, "
                f"跳过 {domains_skipped}, 失败 {domains_failed}, "
                f"耗时 {duration:.1f} 秒"
            )
            
        except Exception as e:
            logger.error(f"监控任务失败: {e}")
            task_manager.fail_task(
                task_date, tier, str(e), domains_checked, domains_failed
            )
            
            # 发送失败通知
            if not dry_run:
                duration = time.time() - start_time
                workflow_summary = WorkflowSummary(
                    tier=tier,
                    task_date=str(task_date),
                    domains_total=domains_total,
                    domains_checked=domains_checked,
                    domains_failed=domains_failed,
                    domains_expiring=domains_expiring,
                    domains_expired=domains_expired,
                    domains_error=domains_error,
                    duration_seconds=duration,
                    domains_skipped=domains_skipped,
                )
                notifier.send_workflow_summary(workflow_summary)
            
            raise


def main():
    """主函数"""
    args = parse_args()
    
    # 解析任务日期
    if args.date:
        task_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    else:
        task_date = date.today()
    
    logger.info(f"SSL Monitor Worker 启动")
    logger.info(f"订阅等级: {args.tier}")
    logger.info(f"任务日期: {task_date}")
    logger.info(f"试运行模式: {args.dry_run}")
    if args.batch_size:
        logger.info(f"批处理大小: {args.batch_size}")
    
    try:
        # 加载配置
        config = load_config()
        
        # 运行监控
        run_monitor(args.tier, task_date, config, args.dry_run, args.batch_size)
        
        logger.info("SSL Monitor Worker 完成")
        
    except DatabaseConnectionError as e:
        logger.error(f"数据库连接失败: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
