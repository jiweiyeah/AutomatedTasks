"""
任务管理模块
管理监控任务的状态和执行
"""
import uuid
import logging
from datetime import datetime, date
from typing import Optional

from .db import DatabaseClient
from .models import TaskLog
from .config import TaskStatus

logger = logging.getLogger(__name__)


class TaskManager:
    """任务状态管理器"""
    
    def __init__(self, db: DatabaseClient):
        """
        初始化任务管理器
        
        Args:
            db: 数据库客户端
        """
        self.db = db
    
    def should_run(self, task_date: date, tier: str) -> bool:
        """
        检查任务是否应该执行
        
        注意：此方法只检查任务级别状态，不检查域名级别进度
        断点续作逻辑在 main.py 中通过 ProgressTracker 实现
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            
        Returns:
            是否应该执行
        """
        existing_log = self.db.get_task_log(task_date, tier)
        
        if existing_log and existing_log.status == TaskStatus.RUNNING:
            logger.warning(
                f"任务正在运行中: {task_date} - {tier}，可能是上次执行未正常结束，将继续执行"
            )
            # 允许重新执行，会更新现有记录
        
        # 即使任务标记为 completed，也允许执行
        # 断点续作逻辑会在 main.py 中检查 domain_check_progress 表
        # 如果所有域名都已完成，会在 main.py 中提前返回
        if existing_log and existing_log.status == TaskStatus.COMPLETED:
            logger.info(
                f"任务已标记完成: {task_date} - {tier}，"
                f"将检查是否有新增或未完成的域名"
            )
        
        return True
    
    def start_task(self, task_date: date, tier: str) -> str:
        """
        开始任务，创建任务日志
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            
        Returns:
            任务 ID
        """
        task_id = str(uuid.uuid4())
        
        log = TaskLog(
            id=task_id,
            task_date=task_date,
            tier=tier,
            status=TaskStatus.RUNNING,
            started_at=datetime.now(),
            domains_checked=0,
            domains_failed=0,
        )
        
        self.db.upsert_task_log(log)
        logger.info(f"任务开始: {task_date} - {tier} (ID: {task_id})")
        
        return task_id
    
    def complete_task(
        self, 
        task_date: date,
        tier: str,
        domains_checked: int, 
        domains_failed: int
    ) -> None:
        """
        完成任务
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            domains_checked: 检查的域名数量
            domains_failed: 失败的域名数量
        """
        existing_log = self.db.get_task_log(task_date, tier)
        
        if not existing_log:
            logger.warning(f"任务日志不存在: {task_date} - {tier}")
            return
        
        log = TaskLog(
            id=existing_log.id,
            task_date=task_date,
            tier=tier,
            status=TaskStatus.COMPLETED,
            started_at=existing_log.started_at,
            completed_at=datetime.now(),
            domains_checked=domains_checked,
            domains_failed=domains_failed,
        )
        
        self.db.upsert_task_log(log)
        logger.info(
            f"任务完成: {task_date} - {tier} "
            f"(检查 {domains_checked} 个，失败 {domains_failed} 个)"
        )
    
    def fail_task(
        self, 
        task_date: date,
        tier: str,
        error_message: str,
        domains_checked: int = 0,
        domains_failed: int = 0
    ) -> None:
        """
        标记任务失败
        
        Args:
            task_date: 任务日期
            tier: 订阅等级
            error_message: 错误信息
            domains_checked: 已检查的域名数量
            domains_failed: 失败的域名数量
        """
        existing_log = self.db.get_task_log(task_date, tier)
        
        if not existing_log:
            logger.warning(f"任务日志不存在: {task_date} - {tier}")
            # 创建一个失败记录
            existing_log = TaskLog(
                id=str(uuid.uuid4()),
                task_date=task_date,
                tier=tier,
                status=TaskStatus.RUNNING,
                started_at=datetime.now(),
            )
        
        log = TaskLog(
            id=existing_log.id,
            task_date=task_date,
            tier=tier,
            status=TaskStatus.FAILED,
            started_at=existing_log.started_at,
            completed_at=datetime.now(),
            domains_checked=domains_checked,
            domains_failed=domains_failed,
            error_message=error_message,
        )
        
        self.db.upsert_task_log(log)
        logger.error(f"任务失败: {task_date} - {tier} - {error_message}")
