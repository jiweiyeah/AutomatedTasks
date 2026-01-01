"""
证书链验证器模块
负责验证证书链的完整性和有效性
与 Next.js lib/ssl/chain-validator.ts 保持一致
"""
import logging
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from .chain_extractor import CertificateChainInfo, ChainCertificate

logger = logging.getLogger(__name__)

# ============================================================================
# 类型定义
# ============================================================================

# 链验证状态
ChainStatus = Literal["complete", "incomplete", "broken"]

# 即将过期的天数阈值
EXPIRING_SOON_DAYS = 30


@dataclass
class CertificateValidation:
    """单个证书的验证结果"""
    index: int                               # 证书在链中的索引
    subject: str                             # 证书主题（用于显示）
    type: str                                # 证书类型
    is_valid: bool                           # 是否有效
    is_expired: bool                         # 是否已过期
    is_expiring_soon: bool                   # 是否即将过期（30天内）
    days_remaining: int                      # 剩余天数
    signature_valid: bool                    # 签名验证是否通过
    issues: List[str] = field(default_factory=list)  # 问题列表


@dataclass
class ChainValidationResult:
    """链验证结果"""
    status: ChainStatus                      # 链状态
    certificates: List[CertificateValidation] = field(default_factory=list)  # 每个证书的验证结果
    earliest_expiring_index: int = -1        # 最早过期的证书索引
    earliest_expiry_date: str = ""           # 最早过期日期 (ISO String)
    earliest_expiry_days: int = 0            # 最早过期证书的剩余天数
    issues: List[str] = field(default_factory=list)  # 整体问题列表


# ============================================================================
# 工具函数
# ============================================================================

def get_certificate_display_name(cert: ChainCertificate) -> str:
    """获取证书的显示名称"""
    return cert.subject.CN or cert.subject.O or "Unknown Certificate"


def is_expired(cert: ChainCertificate) -> bool:
    """检查证书是否已过期"""
    return cert.days_remaining < 0


def is_expiring_soon(cert: ChainCertificate) -> bool:
    """检查证书是否即将过期"""
    return 0 <= cert.days_remaining <= EXPIRING_SOON_DAYS


def validate_chain_signature(
    cert: ChainCertificate,
    issuer_cert: Optional[ChainCertificate],
    is_last_cert: bool
) -> bool:
    """
    验证证书链的签名关系
    检查每个证书的 issuer 是否与下一个证书的 subject 匹配
    """
    if not issuer_cert:
        # 如果是自签名证书，没有颁发者证书是正常的
        if cert.is_self_signed:
            return True
        # 如果是链中最后一个证书且不是自签名，说明缺少根证书
        # 这种情况很常见（服务器通常不发送根证书），不应视为签名失败
        if is_last_cert:
            return True
        return False
    
    # 检查当前证书的 issuer 是否与颁发者证书的 subject 匹配
    issuer_match = (
        cert.issuer.CN == issuer_cert.subject.CN and
        cert.issuer.O == issuer_cert.subject.O
    )
    
    return issuer_match


# ============================================================================
# 核心函数
# ============================================================================

def validate_chain(chain_info: CertificateChainInfo) -> ChainValidationResult:
    """
    验证证书链
    
    Args:
        chain_info: 证书链信息
        
    Returns:
        链验证结果
    """
    issues: List[str] = []
    certificates: List[CertificateValidation] = []
    
    # 空链处理
    if chain_info.chain_length == 0:
        return ChainValidationResult(
            status="broken",
            certificates=[],
            earliest_expiring_index=-1,
            earliest_expiry_date="",
            earliest_expiry_days=0,
            issues=["证书链为空，无法获取证书信息"],
        )
    
    # 跟踪最早过期的证书
    earliest_expiring_index = 0
    earliest_expiry_date = chain_info.chain[0].valid_to
    earliest_expiry_days = chain_info.chain[0].days_remaining
    
    # 验证每个证书
    for index, cert in enumerate(chain_info.chain):
        cert_issues: List[str] = []
        display_name = get_certificate_display_name(cert)
        is_last_cert = index == len(chain_info.chain) - 1
        
        # 检查过期状态
        expired = is_expired(cert)
        expiring_soon = is_expiring_soon(cert)
        
        if expired:
            cert_issues.append(f"证书已过期 {abs(cert.days_remaining)} 天")
        elif expiring_soon:
            cert_issues.append(f"证书将在 {cert.days_remaining} 天内过期")
        
        # 验证签名链（检查与下一个证书的关系）
        next_cert = chain_info.chain[index + 1] if index + 1 < len(chain_info.chain) else None
        signature_valid = validate_chain_signature(cert, next_cert, is_last_cert)
        
        if not signature_valid and not cert.is_self_signed:
            cert_issues.append("证书签名链验证失败")
        
        # 更新最早过期证书
        if cert.days_remaining < earliest_expiry_days:
            earliest_expiring_index = index
            earliest_expiry_date = cert.valid_to
            earliest_expiry_days = cert.days_remaining
        
        # 构建验证结果
        certificates.append(CertificateValidation(
            index=index,
            subject=display_name,
            type=cert.type,
            is_valid=not expired and signature_valid,
            is_expired=expired,
            is_expiring_soon=expiring_soon,
            days_remaining=cert.days_remaining,
            signature_valid=signature_valid,
            issues=cert_issues,
        ))
        
        # 收集问题到整体列表
        for issue in cert_issues:
            issues.append(f"[{cert.type}] {display_name}: {issue}")
    
    # 判断链状态
    status: ChainStatus = "complete"
    
    # 检查链是否完整
    if not chain_info.is_complete:
        if chain_info.root_trusted and chain_info.inferred_root:
            # 根证书受信任，链实际上是完整的
            pass
        else:
            status = "incomplete"
            issues.append("证书链不完整，缺少根证书")
    
    # 检查是否有过期证书
    has_expired = any(c.is_expired for c in certificates)
    if has_expired:
        status = "broken"
    
    # 检查签名链是否有效
    has_invalid_signature = any(not c.signature_valid for c in certificates)
    if has_invalid_signature:
        status = "broken"
    
    # 检查根证书是否受信任
    if not chain_info.root_trusted:
        issues.append("根证书不受系统信任")
        if status == "complete":
            status = "incomplete"
    
    return ChainValidationResult(
        status=status,
        certificates=certificates,
        earliest_expiring_index=earliest_expiring_index,
        earliest_expiry_date=earliest_expiry_date,
        earliest_expiry_days=earliest_expiry_days,
        issues=issues,
    )


def get_validation_summary(result: ChainValidationResult) -> str:
    """获取链验证的简要摘要"""
    status_map = {
        "complete": "✅ 证书链完整",
        "incomplete": "⚠️ 证书链不完整",
        "broken": "❌ 证书链断裂",
    }
    
    parts = [status_map[result.status]]
    
    if result.earliest_expiry_days < 0:
        parts.append(f"最早过期: 已过期 {abs(result.earliest_expiry_days)} 天")
    elif result.earliest_expiry_days <= EXPIRING_SOON_DAYS:
        parts.append(f"最早过期: {result.earliest_expiry_days} 天后")
    
    if result.issues:
        parts.append(f"发现 {len(result.issues)} 个问题")
    
    return " | ".join(parts)
