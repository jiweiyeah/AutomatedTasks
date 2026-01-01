"""
批量处理模块
支持并行批量处理域名检测，提高执行效率
"""
import logging
import time
from dataclasses import dataclass, field
from typing import List, Callable, Any, Optional, TypeVar, Generic
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

T = TypeVar('T')  # 输入类型
R = TypeVar('R')  # 结果类型


@dataclass
class BatchConfig:
    """批处理配置"""
    batch_size: int = 10           # 每批并发数量
    rate_limit_delay: float = 0.1  # 请求间隔（秒），避免过快请求
    max_workers: int = 10          # 最大工作线程数


@dataclass
class BatchResult:
    """单个处理结果"""
    item_id: str                   # 项目标识（如域名 ID）
    success: bool                  # 是否成功
    result: Any = None             # 处理结果
    error: Optional[str] = None    # 错误信息
    duration: float = 0.0          # 处理耗时（秒）


@dataclass
class BatchSummary:
    """批次处理汇总"""
    total: int = 0
    success: int = 0
    failed: int = 0
    duration: float = 0.0
    results: List[BatchResult] = field(default_factory=list)


class BatchProcessor:
    """
    批量处理器
    使用 ThreadPoolExecutor 实现并发处理
    """
    
    def __init__(self, config: Optional[BatchConfig] = None):
        """
        初始化批处理器
        
        Args:
            config: 批处理配置，默认使用 BatchConfig 默认值
        """
        self.config = config or BatchConfig()
    
    def divide_into_batches(
        self, 
        items: List[T], 
        batch_size: Optional[int] = None
    ) -> List[List[T]]:
        """
        将列表分割成批次
        
        Args:
            items: 待处理项目列表
            batch_size: 每批大小，默认使用配置值
            
        Returns:
            批次列表
        """
        size = batch_size or self.config.batch_size
        if size <= 0:
            size = 1
        
        batches = []
        for i in range(0, len(items), size):
            batches.append(items[i:i + size])
        
        return batches

    
    def process_batch(
        self,
        batch: List[T],
        process_func: Callable[[T], BatchResult],
        on_item_complete: Optional[Callable[[BatchResult], None]] = None
    ) -> List[BatchResult]:
        """
        并发处理一个批次
        
        Args:
            batch: 待处理项目批次
            process_func: 处理函数，接收单个项目，返回 BatchResult
            on_item_complete: 单个项目完成时的回调（可选）
            
        Returns:
            处理结果列表
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # 提交所有任务
            future_to_item = {
                executor.submit(self._process_with_delay, process_func, item, idx): item
                for idx, item in enumerate(batch)
            }
            
            # 收集结果
            for future in as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if on_item_complete:
                        on_item_complete(result)
                        
                except Exception as e:
                    # 处理未捕获的异常
                    item = future_to_item[future]
                    item_id = getattr(item, 'id', str(item))
                    error_result = BatchResult(
                        item_id=item_id,
                        success=False,
                        error=str(e)
                    )
                    results.append(error_result)
                    logger.error(f"处理项目 {item_id} 时发生未捕获异常: {e}")
        
        return results
    
    def _process_with_delay(
        self, 
        process_func: Callable[[T], BatchResult], 
        item: T,
        index: int
    ) -> BatchResult:
        """
        带延迟的处理函数，用于速率限制
        
        Args:
            process_func: 处理函数
            item: 待处理项目
            index: 项目在批次中的索引
            
        Returns:
            处理结果
        """
        # 根据索引添加延迟，避免同时发起大量请求
        if index > 0 and self.config.rate_limit_delay > 0:
            time.sleep(self.config.rate_limit_delay * index)
        
        start_time = time.time()
        try:
            result = process_func(item)
            result.duration = time.time() - start_time
            return result
        except Exception as e:
            item_id = getattr(item, 'id', str(item))
            return BatchResult(
                item_id=item_id,
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
    
    def process_all(
        self,
        items: List[T],
        process_func: Callable[[T], BatchResult],
        on_batch_complete: Optional[Callable[[int, List[BatchResult]], None]] = None,
        on_item_complete: Optional[Callable[[BatchResult], None]] = None
    ) -> BatchSummary:
        """
        处理所有项目，分批并发执行
        
        Args:
            items: 待处理项目列表
            process_func: 处理函数
            on_batch_complete: 批次完成时的回调，参数为 (批次索引, 结果列表)
            on_item_complete: 单个项目完成时的回调
            
        Returns:
            处理汇总
        """
        if not items:
            return BatchSummary()
        
        start_time = time.time()
        batches = self.divide_into_batches(items)
        all_results = []
        
        logger.info(f"开始批量处理: 共 {len(items)} 个项目，分 {len(batches)} 批")
        
        for batch_idx, batch in enumerate(batches):
            logger.info(f"处理第 {batch_idx + 1}/{len(batches)} 批，共 {len(batch)} 个项目")
            
            batch_results = self.process_batch(batch, process_func, on_item_complete)
            all_results.extend(batch_results)
            
            # 批次完成回调
            if on_batch_complete:
                on_batch_complete(batch_idx, batch_results)
            
            # 批次间短暂休息，避免过度占用资源
            if batch_idx < len(batches) - 1:
                time.sleep(0.5)
        
        # 统计结果
        summary = BatchSummary(
            total=len(all_results),
            success=sum(1 for r in all_results if r.success),
            failed=sum(1 for r in all_results if not r.success),
            duration=time.time() - start_time,
            results=all_results
        )
        
        logger.info(
            f"批量处理完成: 成功 {summary.success}/{summary.total}，"
            f"耗时 {summary.duration:.1f} 秒"
        )
        
        return summary
