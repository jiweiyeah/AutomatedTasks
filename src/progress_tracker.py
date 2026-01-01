"""
进度追踪模块
管理域名级别的检测进度，支持断点续作
"""
import uuid
import logging
from datetime import datetime, date, timezone
from typing import Dict, Set, List, Optional

from .models import DomainProgress, DomainCheckStatus

logger = logging.getLogger(__name__)


class ProgressTracker:
    """
    域名检测进度追踪器
    负责管理域名级别的检测进度，实现断点续作机制
    """
    
    def __init__(self, db, task_date: date, tier: str):
        """
        初始化进度追踪器
        
        Args:
            db: 数据库客户端
            task_date: 任务日期
            tier: 订阅等级
        """
        self.db = db
        self.task_date = task_date
        self.tier = tier
        # 内存缓存，减少数据库查询
        self._progress_cache: Dict[str, DomainProgress] = {}
        self._loaded = False
    
    def load_existing_progress(self) -> Dict[str, DomainProgress]:
        """
        加载当前任务日期和等级的所有进度记录
        
        Returns:
            域名ID -> 进度记录的字典
        """
        if self._loaded:
            return self._progress_cache
        
        progress_list = self.db.get_domain_progress(self.task_date, self.tier)
        self._progress_cache = {p.domain_id: p for p in progress_list}
        self._loaded = True
        
        logger.info(f"加载现有进度记录: {len(self._progress_cache)} 条")
        return self._progress_cache
    
    def get_completed_domain_ids(self) -> Set[str]:
        """
        获取已完成检测的域名 ID 集合
        
        Returns:
            已完成域名的 ID 集合
        """
        self.load_existing_progress()
        return {
            domain_id 
            for domain_id, progress in self._progress_cache.items()
            if progress.status == DomainCheckStatus.COMPLETED.value
        }
    
    def get_notified_domain_ids(self) -> Set[str]:
        """
        获取已发送通知的域名 ID 集合
        
        Returns:
            已发送通知的域名 ID 集合
        """
        self.load_existing_progress()
        return {
            domain_id 
            for domain_id, progress in self._progress_cache.items()
            if progress.notification_sent
        }
    
    def is_domain_completed(self, domain_id: str) -> bool:
        """检查域名是否已完成检测"""
        self.load_existing_progress()
        progress = self._progress_cache.get(domain_id)
        return progress is not None and progress.status == DomainCheckStatus.COMPLETED.value
    
    def is_notification_sent(self, domain_id: str) -> bool:
        """检查域名是否已发送通知"""
        self.load_existing_progress()
        progress = self._progress_cache.get(domain_id)
        return progress is not None and progress.notification_sent

    
    def mark_checking(self, domain_id: str) -> None:
        """
        标记域名为检测中状态
        
        Args:
            domain_id: 域名 ID
        """
        now = datetime.now(timezone.utc)
        progress = self._get_or_create_progress(domain_id)
        progress.status = DomainCheckStatus.CHECKING.value
        progress.updated_at = now
        
        self.db.upsert_domain_progress(progress)
        self._progress_cache[domain_id] = progress
        
        logger.debug(f"域名 {domain_id} 标记为检测中")
    
    def mark_completed(
        self, 
        domain_id: str, 
        ssl_status: str,
        checked_at: Optional[datetime] = None
    ) -> None:
        """
        标记域名检测完成
        
        Args:
            domain_id: 域名 ID
            ssl_status: SSL 证书状态 (valid/expiring/expired/error)
            checked_at: 检测完成时间，默认为当前时间
        """
        now = datetime.now(timezone.utc)
        progress = self._get_or_create_progress(domain_id)
        progress.status = DomainCheckStatus.COMPLETED.value
        progress.ssl_status = ssl_status
        progress.checked_at = checked_at or now
        progress.updated_at = now
        progress.error_message = None  # 清除之前的错误
        
        self.db.upsert_domain_progress(progress)
        self._progress_cache[domain_id] = progress
        
        logger.debug(f"域名 {domain_id} 检测完成: {ssl_status}")
    
    def mark_failed(self, domain_id: str, error_message: str) -> None:
        """
        标记域名检测失败
        
        Args:
            domain_id: 域名 ID
            error_message: 错误信息
        """
        now = datetime.now(timezone.utc)
        progress = self._get_or_create_progress(domain_id)
        progress.status = DomainCheckStatus.FAILED.value
        progress.error_message = error_message
        progress.updated_at = now
        
        self.db.upsert_domain_progress(progress)
        self._progress_cache[domain_id] = progress
        
        logger.debug(f"域名 {domain_id} 检测失败: {error_message}")
    
    def mark_notification_sent(self, domain_id: str) -> None:
        """
        标记域名已发送通知
        
        Args:
            domain_id: 域名 ID
        """
        now = datetime.now(timezone.utc)
        progress = self._progress_cache.get(domain_id)
        
        if not progress:
            logger.warning(f"域名 {domain_id} 进度记录不存在，无法标记通知状态")
            return
        
        progress.notification_sent = True
        progress.updated_at = now
        
        self.db.upsert_domain_progress(progress)
        self._progress_cache[domain_id] = progress
        
        logger.debug(f"域名 {domain_id} 已标记为已发送通知")
    
    def _get_or_create_progress(self, domain_id: str) -> DomainProgress:
        """
        获取或创建域名进度记录
        
        Args:
            domain_id: 域名 ID
            
        Returns:
            域名进度记录
        """
        self.load_existing_progress()
        
        if domain_id in self._progress_cache:
            return self._progress_cache[domain_id]
        
        # 创建新记录
        now = datetime.now(timezone.utc)
        progress = DomainProgress(
            id=str(uuid.uuid4()),
            task_date=self.task_date,
            tier=self.tier,
            domain_id=domain_id,
            status=DomainCheckStatus.PENDING.value,
            notification_sent=False,
            created_at=now,
            updated_at=now,
        )
        
        return progress

    
    def batch_update_progress(self, updates: List[DomainProgress]) -> int:
        """
        批量更新进度记录
        
        Args:
            updates: 进度记录列表
            
        Returns:
            更新的记录数
        """
        if not updates:
            return 0
        
        count = self.db.batch_upsert_domain_progress(updates)
        
        # 更新缓存
        for progress in updates:
            self._progress_cache[progress.domain_id] = progress
        
        logger.debug(f"批量更新 {count} 条进度记录")
        return count
    
    def get_resume_stats(self) -> Dict[str, int]:
        """
        获取恢复统计信息
        
        Returns:
            包含各状态数量的字典
        """
        self.load_existing_progress()
        
        stats = {
            "total": len(self._progress_cache),
            "pending": 0,
            "checking": 0,
            "completed": 0,
            "failed": 0,
            "notification_sent": 0,
        }
        
        for progress in self._progress_cache.values():
            status = progress.status
            if status in stats:
                stats[status] += 1
            if progress.notification_sent:
                stats["notification_sent"] += 1
        
        return stats
    
    def log_resume_info(self, total_domains: int) -> None:
        """
        记录恢复信息日志
        
        Args:
            total_domains: 该等级的总域名数
        """
        stats = self.get_resume_stats()
        completed = stats["completed"]
        remaining = total_domains - completed
        
        if completed > 0:
            logger.info(
                f"断点续作: 已完成 {completed} 个域名，"
                f"剩余 {remaining} 个待处理"
            )
            logger.info(
                f"进度详情: 待检测={stats['pending']}, "
                f"检测中={stats['checking']}, "
                f"已完成={stats['completed']}, "
                f"失败={stats['failed']}, "
                f"已通知={stats['notification_sent']}"
            )
        else:
            logger.info(f"新任务: 共 {total_domains} 个域名待检测")
