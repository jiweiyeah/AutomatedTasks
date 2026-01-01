"""
数据模型定义
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from enum import Enum


class DomainCheckStatus(Enum):
    """域名检测状态枚举"""
    PENDING = "pending"      # 待检测
    CHECKING = "checking"    # 检测中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"        # 检测失败


@dataclass
class DomainWithUser:
    """域名及其所属用户信息"""
    id: str
    domain: str
    user_id: str
    user_email: str
    user_plan: str
    is_active: bool
    notes: Optional[str] = None


# ============================================================================
# 证书链相关数据模型 - 与 Next.js 保持一致
# ============================================================================

@dataclass
class CertificateSubjectRecord:
    """证书主题/颁发者信息（用于数据库存储）"""
    CN: Optional[str] = None  # Common Name
    O: Optional[str] = None   # Organization
    OU: Optional[str] = None  # Organizational Unit
    C: Optional[str] = None   # Country
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            "CN": self.CN,
            "O": self.O,
            "OU": self.OU,
            "C": self.C,
        }.items() if v is not None}
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class ChainCertificateRecord:
    """单个证书信息（用于数据库存储）"""
    type: str                                # leaf, intermediate, root
    subject: CertificateSubjectRecord
    issuer: CertificateSubjectRecord
    valid_from: str                          # ISO String
    valid_to: str                            # ISO String
    days_remaining: int
    serial_number: str
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_bits: Optional[int] = None
    is_self_signed: bool = False
    fingerprint_sha256: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "subject": self.subject.to_dict(),
            "issuer": self.issuer.to_dict(),
            "validFrom": self.valid_from,
            "validTo": self.valid_to,
            "daysRemaining": self.days_remaining,
            "serialNumber": self.serial_number,
            "signatureAlgorithm": self.signature_algorithm,
            "publicKeyAlgorithm": self.public_key_algorithm,
            "keyBits": self.key_bits,
            "isSelfSigned": self.is_self_signed,
            "fingerprint256": self.fingerprint_sha256,
        }


@dataclass
class CertificateChainRecord:
    """证书链信息（用于数据库存储）"""
    chain: List[ChainCertificateRecord] = field(default_factory=list)
    chain_length: int = 0
    is_complete: bool = False
    root_trusted: bool = False
    inferred_root_name: Optional[str] = None
    inferred_root_org: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "chain": [c.to_dict() for c in self.chain],
            "chainLength": self.chain_length,
            "isComplete": self.is_complete,
            "rootTrusted": self.root_trusted,
        }
        if self.inferred_root_name:
            result["inferredRoot"] = {
                "name": self.inferred_root_name,
                "organization": self.inferred_root_org,
                "trusted": self.root_trusted,
            }
        return result
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class ChainValidationRecord:
    """链验证结果（用于数据库存储）"""
    status: str                              # complete, incomplete, broken
    earliest_expiring_index: int = -1
    earliest_expiry_date: str = ""
    earliest_expiry_days: int = 0
    issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "earliestExpiringIndex": self.earliest_expiring_index,
            "earliestExpiryDate": self.earliest_expiry_date,
            "earliestExpiryDays": self.earliest_expiry_days,
            "issues": self.issues,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class SecurityScoreRecord:
    """安全评分（用于数据库存储）"""
    grade: str                               # A+, A, A-, B, C, D, F
    numeric_score: int                       # 0-100
    has_critical_issues: bool = False
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "numericScore": self.numeric_score,
            "hasCriticalIssues": self.has_critical_issues,
            "recommendations": self.recommendations,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class SSLCheckRecord:
    """SSL 检查记录 - 与 Next.js sslChecks 表保持一致"""
    id: str
    domain_id: str
    status: str
    is_valid: bool
    checked_at: datetime
    issuer: Optional[str] = None  # 颁发者 CN 或 O
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_remaining: Optional[int] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint: Optional[str] = None  # SHA-1 指纹
    fingerprint_sha256: Optional[str] = None  # SHA-256 指纹
    issuer_org: Optional[str] = None  # 颁发机构组织名称
    subject_alt_names: Optional[str] = None  # SAN 列表，逗号分隔
    bits: Optional[int] = None  # 公钥位数
    ext_key_usage: Optional[str] = None  # 扩展密钥用法，JSON 数组字符串
    ocsp_uri: Optional[str] = None  # OCSP URL
    ca_issuers_uri: Optional[str] = None  # CA 颁发者 URL
    asn1_curve: Optional[str] = None  # ASN.1 曲线名称（仅 ECC）
    nist_curve: Optional[str] = None  # NIST 曲线名称（仅 ECC）
    error_message: Optional[str] = None
    # ========== 安全评分相关字段 ==========
    security_grade: Optional[str] = None       # 安全评级: A+, A, A-, B, C, D, F
    security_score: Optional[int] = None       # 安全评分 (0-100)
    has_critical_issues: Optional[bool] = None # 是否有严重安全问题
    security_details: Optional[str] = None     # 安全评分详情 (JSON)
    # ========== 证书链相关字段 ==========
    chain_length: Optional[int] = None         # 证书链长度
    chain_complete: Optional[bool] = None      # 证书链是否完整
    chain_details: Optional[str] = None        # 证书链详情 (JSON)
    # ========== 加密分析相关字段 ==========
    protocol_secure: Optional[bool] = None     # 协议是否安全
    cipher_secure: Optional[bool] = None       # 加密套件是否安全
    overall_risk: Optional[str] = None         # 整体风险等级: critical, high, medium, low, none
    cipher_details: Optional[str] = None       # 加密分析详情 (JSON)


@dataclass
class NotificationChannel:
    """通知渠道"""
    id: str
    user_id: str
    channel_type: str
    enabled: bool
    verified: bool
    encrypted_config: Optional[str] = None


@dataclass
class NotificationLogRecord:
    """通知日志记录"""
    id: str
    channel_id: str
    notification_type: str
    status: str
    sent_at: datetime
    error_message: Optional[str] = None
    metadata: Optional[str] = None


@dataclass
class SystemMessageRecord:
    """系统消息记录"""
    id: str
    user_id: str
    title: str
    message: str
    severity: str
    is_read: bool = False
    metadata: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class TaskLog:
    """任务执行日志"""
    id: str
    task_date: date
    tier: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    domains_checked: int = 0
    domains_failed: int = 0
    error_message: Optional[str] = None


@dataclass
class DomainProgress:
    """
    域名检测进度记录
    用于实现断点续作机制，记录每个域名在每次任务中的检测状态
    """
    id: str
    task_date: date
    tier: str
    domain_id: str
    status: str  # pending, checking, completed, failed
    ssl_status: Optional[str] = None  # valid, expiring, expired, error
    checked_at: Optional[datetime] = None
    notification_sent: bool = False
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
