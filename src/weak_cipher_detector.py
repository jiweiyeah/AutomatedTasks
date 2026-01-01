"""
弱加密检测器模块
负责检测证书和 TLS 连接中使用的弱加密算法
与 Next.js lib/ssl/weak-cipher-detector.ts 保持一致
"""
import logging
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from .chain_extractor import CertificateChainInfo

logger = logging.getLogger(__name__)

# ============================================================================
# 类型定义
# ============================================================================

# 风险等级
RiskLevel = Literal["critical", "high", "medium", "low", "none"]

# 弱加密问题类型
WeakCipherIssueType = Literal["signature_algorithm", "key_length", "cipher_suite", "protocol"]


@dataclass
class WeakCipherIssue:
    """弱加密问题"""
    type: WeakCipherIssueType                # 问题类型
    risk_level: RiskLevel                    # 风险等级
    detected: str                            # 检测到的值
    description: str                         # 问题描述
    recommendation: str                      # 改进建议


@dataclass
class ProtocolSecurity:
    """协议安全状态"""
    version: str                             # 协议版本
    is_secure: bool                          # 是否安全
    risk_level: RiskLevel                    # 风险等级
    recommendation: Optional[str] = None     # 建议


@dataclass
class CipherSecurityResult:
    """加密安全检测结果"""
    protocol: ProtocolSecurity               # 协议安全状态
    cipher_suite: str                        # 加密套件名称
    cipher_secure: bool                      # 加密套件是否安全
    issues: List[WeakCipherIssue] = field(default_factory=list)  # 检测到的问题列表
    overall_risk: RiskLevel = "none"         # 整体风险等级


# ============================================================================
# 常量配置
# ============================================================================

# 弱加密算法黑名单
WEAK_ALGORITHMS = {
    # 弱签名算法
    "signature": ["MD5", "SHA1", "SHA-1", "md5", "sha1"],
    # 弱加密套件关键字
    "cipher": ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "AECDH"],
    # 不安全协议版本
    "protocol": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"],
}

# 最小安全密钥长度 (bits)
MIN_KEY_BITS = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256,
    "ECDSA": 256,
    "ECDH": 256,
}


# ============================================================================
# 工具函数
# ============================================================================

def check_signature_algorithm(algorithm: Optional[str]) -> Optional[WeakCipherIssue]:
    """检测签名算法是否为弱算法"""
    if not algorithm:
        return None
    
    upper_algo = algorithm.upper()
    
    # 检查 MD5
    if "MD5" in upper_algo:
        return WeakCipherIssue(
            type="signature_algorithm",
            risk_level="critical",
            detected=algorithm,
            description="使用了已废弃的 MD5 签名算法，存在碰撞攻击风险",
            recommendation="更换为使用 SHA-256 或更强签名算法的证书",
        )
    
    # 检查 SHA-1
    if "SHA1" in upper_algo or "SHA-1" in upper_algo:
        return WeakCipherIssue(
            type="signature_algorithm",
            risk_level="high",
            detected=algorithm,
            description="使用了已废弃的 SHA-1 签名算法，存在碰撞攻击风险",
            recommendation="更换为使用 SHA-256 或更强签名算法的证书",
        )
    
    return None


def check_key_length(
    key_bits: Optional[int],
    algorithm: Optional[str] = None
) -> Optional[WeakCipherIssue]:
    """检测密钥长度是否满足安全要求"""
    if not key_bits:
        return None
    
    # 根据算法类型确定最小密钥长度
    min_bits = MIN_KEY_BITS["RSA"]  # 默认使用 RSA 标准
    key_type = "RSA"
    
    if algorithm:
        upper_algo = algorithm.upper()
        if "EC" in upper_algo or "ECDSA" in upper_algo or "ECDH" in upper_algo:
            min_bits = MIN_KEY_BITS["EC"]
            key_type = "ECC"
        elif "DSA" in upper_algo:
            min_bits = MIN_KEY_BITS["DSA"]
            key_type = "DSA"
    
    # 如果密钥长度较小（<= 521），很可能是 ECC 密钥
    if key_bits <= 521 and key_type == "RSA":
        key_type = "ECC"
        min_bits = MIN_KEY_BITS["EC"]
    
    if key_bits < min_bits:
        risk_level: RiskLevel = "critical" if key_bits < min_bits // 2 else "high"
        return WeakCipherIssue(
            type="key_length",
            risk_level=risk_level,
            detected=f"{key_bits} bits",
            description=f"{key_type} 密钥长度 {key_bits} 位低于推荐的 {min_bits} 位",
            recommendation=f"使用至少 {min_bits} 位的 {key_type} 密钥",
        )
    
    return None


def check_cipher_suite(cipher_suite: str) -> Optional[WeakCipherIssue]:
    """检测加密套件是否包含弱算法"""
    if not cipher_suite:
        return None
    
    upper_cipher = cipher_suite.upper()
    
    for weak_cipher in WEAK_ALGORITHMS["cipher"]:
        if weak_cipher.upper() in upper_cipher:
            risk_level: RiskLevel = "high"
            description = ""
            recommendation = ""
            
            weak_upper = weak_cipher.upper()
            if weak_upper == "NULL":
                risk_level = "critical"
                description = "使用了 NULL 加密，数据未加密传输"
                recommendation = "配置服务器禁用 NULL 加密套件"
            elif weak_upper == "EXPORT":
                risk_level = "critical"
                description = "使用了出口级弱加密，密钥长度不足"
                recommendation = "配置服务器禁用 EXPORT 加密套件"
            elif weak_upper == "RC4":
                risk_level = "high"
                description = "使用了已废弃的 RC4 流加密算法"
                recommendation = "配置服务器禁用 RC4，使用 AES-GCM"
            elif weak_upper in ("DES", "3DES"):
                risk_level = "high"
                description = "使用了已废弃的 DES/3DES 加密算法"
                recommendation = "配置服务器禁用 DES/3DES，使用 AES-GCM"
            elif weak_upper in ("ANON", "ADH", "AECDH"):
                risk_level = "critical"
                description = "使用了匿名加密套件，无身份验证"
                recommendation = "配置服务器禁用匿名加密套件"
            else:
                description = f"使用了不安全的加密算法: {weak_cipher}"
                recommendation = "更新服务器加密套件配置"
            
            return WeakCipherIssue(
                type="cipher_suite",
                risk_level=risk_level,
                detected=cipher_suite,
                description=description,
                recommendation=recommendation,
            )
    
    return None


def check_protocol_version(protocol: str) -> ProtocolSecurity:
    """检测协议版本安全性"""
    if not protocol:
        return ProtocolSecurity(
            version="Unknown",
            is_secure=False,
            risk_level="medium",
            recommendation="无法确定协议版本",
        )
    
    # 标准化协议版本字符串
    normalized_protocol = protocol.replace(" ", "")
    
    # 检查 TLS 1.3 和 1.2（安全版本）
    if "TLSv1.3" in normalized_protocol:
        return ProtocolSecurity(
            version=protocol,
            is_secure=True,
            risk_level="none",
        )
    
    if "TLSv1.2" in normalized_protocol:
        return ProtocolSecurity(
            version=protocol,
            is_secure=True,
            risk_level="none",
        )
    
    # 检查不安全版本
    if "TLSv1.1" in normalized_protocol:
        return ProtocolSecurity(
            version=protocol,
            is_secure=False,
            risk_level="high",
            recommendation="升级到 TLS 1.2 或 TLS 1.3",
        )
    
    if "TLSv1.0" in normalized_protocol or normalized_protocol == "TLSv1":
        return ProtocolSecurity(
            version=protocol,
            is_secure=False,
            risk_level="high",
            recommendation="升级到 TLS 1.2 或 TLS 1.3",
        )
    
    if "SSLv3" in normalized_protocol:
        return ProtocolSecurity(
            version=protocol,
            is_secure=False,
            risk_level="critical",
            recommendation="立即升级到 TLS 1.2 或 TLS 1.3",
        )
    
    if "SSLv2" in normalized_protocol:
        return ProtocolSecurity(
            version=protocol,
            is_secure=False,
            risk_level="critical",
            recommendation="立即升级到 TLS 1.2 或 TLS 1.3",
        )
    
    # 未知协议，假设为安全
    return ProtocolSecurity(
        version=protocol,
        is_secure=True,
        risk_level="none",
    )


def calculate_overall_risk(
    issues: List[WeakCipherIssue],
    protocol: ProtocolSecurity
) -> RiskLevel:
    """计算整体风险等级"""
    risk_priority: List[RiskLevel] = ["critical", "high", "medium", "low", "none"]
    
    # 收集所有风险等级
    risks: List[RiskLevel] = [protocol.risk_level] + [i.risk_level for i in issues]
    
    # 返回最高风险等级
    for risk in risk_priority:
        if risk in risks:
            return risk
    
    return "none"


# ============================================================================
# 核心函数
# ============================================================================

def detect_weak_ciphers(
    chain_info: CertificateChainInfo,
    protocol: str,
    cipher: str
) -> CipherSecurityResult:
    """
    检测弱加密
    
    Args:
        chain_info: 证书链信息
        protocol: TLS 协议版本
        cipher: 加密套件名称
        
    Returns:
        加密安全检测结果
    """
    issues: List[WeakCipherIssue] = []
    
    # 1. 检测协议版本
    protocol_security = check_protocol_version(protocol)
    if protocol_security.risk_level != "none":
        issues.append(WeakCipherIssue(
            type="protocol",
            risk_level=protocol_security.risk_level,
            detected=protocol,
            description=f"使用了不安全的协议版本: {protocol}",
            recommendation=protocol_security.recommendation or "升级到 TLS 1.2 或 TLS 1.3",
        ))
    
    # 2. 检测加密套件
    cipher_issue = check_cipher_suite(cipher)
    if cipher_issue:
        issues.append(cipher_issue)
    
    # 3. 检测证书链中每个证书的签名算法和密钥长度
    for index, cert in enumerate(chain_info.chain):
        cert_name = cert.subject.CN or cert.subject.O or f"Certificate {index}"
        
        # 检测签名算法
        sig_issue = check_signature_algorithm(cert.signature_algorithm)
        if sig_issue:
            sig_issue.description = f"[{cert.type}] {cert_name}: {sig_issue.description}"
            issues.append(sig_issue)
        
        # 检测密钥长度
        key_issue = check_key_length(cert.key_bits, cert.signature_algorithm)
        if key_issue:
            key_issue.description = f"[{cert.type}] {cert_name}: {key_issue.description}"
            issues.append(key_issue)
    
    # 4. 计算整体风险等级
    overall_risk = calculate_overall_risk(issues, protocol_security)
    
    # 5. 判断加密套件是否安全
    cipher_secure = cipher_issue is None
    
    return CipherSecurityResult(
        protocol=protocol_security,
        cipher_suite=cipher,
        cipher_secure=cipher_secure,
        issues=issues,
        overall_risk=overall_risk,
    )


def get_cipher_security_summary(result: CipherSecurityResult) -> str:
    """获取加密安全检测的简要摘要"""
    risk_labels = {
        "critical": "🔴 严重风险",
        "high": "🟠 高风险",
        "medium": "🟡 中等风险",
        "low": "🟢 低风险",
        "none": "✅ 安全",
    }
    
    parts = [
        f"协议: {result.protocol.version}",
        f"风险等级: {risk_labels[result.overall_risk]}",
    ]
    
    if result.issues:
        parts.append(f"发现 {len(result.issues)} 个安全问题")
    
    return " | ".join(parts)
