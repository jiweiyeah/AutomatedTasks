"""
安全评分器模块
基于所有检测结果计算综合安全评分
与 Next.js lib/ssl/security-scorer.ts 保持一致
"""
import logging
from dataclasses import dataclass, field
from typing import List, Literal, Dict

from .chain_validator import ChainValidationResult
from .weak_cipher_detector import CipherSecurityResult, RiskLevel

logger = logging.getLogger(__name__)

# ============================================================================
# 类型定义
# ============================================================================

# 安全评级 (A+ 到 F)
SecurityGrade = Literal["A+", "A", "A-", "B", "C", "D", "F"]

# 评分分类
ScoreCategory = Literal["certificate", "chain", "cipher", "protocol"]


@dataclass
class ScoreBreakdown:
    """评分分解项"""
    category: ScoreCategory                  # 分类
    category_name: str                       # 分类名称（用于显示）
    score: int                               # 分数 (0-100)
    weight: float                            # 权重
    weighted_score: float                    # 加权分数
    deductions: List[str] = field(default_factory=list)  # 扣分原因


@dataclass
class SecurityScore:
    """安全评分结果"""
    grade: SecurityGrade                     # 最终评级
    numeric_score: int                       # 数值分数 (0-100)
    breakdown: List[ScoreBreakdown] = field(default_factory=list)  # 分数分解
    has_critical_issues: bool = False        # 是否有严重问题
    recommendations: List[str] = field(default_factory=list)  # 改进建议列表


# ============================================================================
# 常量配置
# ============================================================================

# 评分权重配置
SCORE_WEIGHTS: Dict[ScoreCategory, float] = {
    "certificate": 0.3,   # 证书有效性 30%
    "chain": 0.25,        # 链完整性 25%
    "cipher": 0.25,       # 加密强度 25%
    "protocol": 0.2,      # 协议版本 20%
}

# 分类名称映射
CATEGORY_NAMES: Dict[ScoreCategory, str] = {
    "certificate": "证书有效性",
    "chain": "链完整性",
    "cipher": "加密强度",
    "protocol": "协议版本",
}

# 评级阈值
GRADE_THRESHOLDS: List[tuple] = [
    (95, "A+"),
    (90, "A"),
    (85, "A-"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0, "F"),
]

# 风险等级对应的扣分
RISK_DEDUCTIONS: Dict[RiskLevel, int] = {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5,
    "none": 0,
}


# ============================================================================
# 工具函数
# ============================================================================

def calculate_certificate_score(chain_validation: ChainValidationResult) -> ScoreBreakdown:
    """计算证书有效性分数"""
    score = 100
    deductions: List[str] = []
    
    # 检查是否有过期证书
    expired_certs = [c for c in chain_validation.certificates if c.is_expired]
    if expired_certs:
        score -= 50
        deductions.append(f"{len(expired_certs)} 个证书已过期")
    
    # 检查是否有即将过期的证书
    expiring_soon_certs = [
        c for c in chain_validation.certificates 
        if c.is_expiring_soon and not c.is_expired
    ]
    if expiring_soon_certs:
        score -= 10 * len(expiring_soon_certs)
        deductions.append(f"{len(expiring_soon_certs)} 个证书即将过期")
    
    # 检查最早过期时间
    if chain_validation.earliest_expiry_days < 0:
        score -= 20
    elif chain_validation.earliest_expiry_days <= 7:
        score -= 15
        deductions.append("证书将在 7 天内过期")
    elif chain_validation.earliest_expiry_days <= 14:
        score -= 10
        deductions.append("证书将在 14 天内过期")
    
    final_score = max(0, score)
    return ScoreBreakdown(
        category="certificate",
        category_name=CATEGORY_NAMES["certificate"],
        score=final_score,
        weight=SCORE_WEIGHTS["certificate"],
        weighted_score=final_score * SCORE_WEIGHTS["certificate"],
        deductions=deductions,
    )


def calculate_chain_score(chain_validation: ChainValidationResult) -> ScoreBreakdown:
    """计算链完整性分数"""
    score = 100
    deductions: List[str] = []
    
    # 根据链状态扣分
    if chain_validation.status == "broken":
        score -= 50
        deductions.append("证书链断裂")
    elif chain_validation.status == "incomplete":
        score -= 25
        deductions.append("证书链不完整")
    
    # 检查签名验证
    invalid_signatures = [c for c in chain_validation.certificates if not c.signature_valid]
    if invalid_signatures:
        score -= 30
        deductions.append(f"{len(invalid_signatures)} 个证书签名验证失败")
    
    final_score = max(0, score)
    return ScoreBreakdown(
        category="chain",
        category_name=CATEGORY_NAMES["chain"],
        score=final_score,
        weight=SCORE_WEIGHTS["chain"],
        weighted_score=final_score * SCORE_WEIGHTS["chain"],
        deductions=deductions,
    )


def calculate_cipher_score(cipher_security: CipherSecurityResult) -> ScoreBreakdown:
    """计算加密强度分数"""
    score = 100
    deductions: List[str] = []
    
    # 根据加密套件问题扣分
    cipher_issues = [
        i for i in cipher_security.issues 
        if i.type in ("cipher_suite", "signature_algorithm", "key_length")
    ]
    
    for issue in cipher_issues:
        deduction = RISK_DEDUCTIONS[issue.risk_level]
        score -= deduction
        deductions.append(issue.description)
    
    # 加密套件不安全额外扣分
    if not cipher_security.cipher_secure:
        score -= 10
    
    final_score = max(0, score)
    return ScoreBreakdown(
        category="cipher",
        category_name=CATEGORY_NAMES["cipher"],
        score=final_score,
        weight=SCORE_WEIGHTS["cipher"],
        weighted_score=final_score * SCORE_WEIGHTS["cipher"],
        deductions=deductions,
    )


def calculate_protocol_score(cipher_security: CipherSecurityResult) -> ScoreBreakdown:
    """计算协议版本分数"""
    score = 100
    deductions: List[str] = []
    
    # 根据协议安全性扣分
    if not cipher_security.protocol.is_secure:
        deduction = RISK_DEDUCTIONS[cipher_security.protocol.risk_level]
        score -= deduction
        deductions.append(f"使用不安全协议: {cipher_security.protocol.version}")
    
    # 协议相关的问题
    protocol_issues = [i for i in cipher_security.issues if i.type == "protocol"]
    for issue in protocol_issues:
        if not any(issue.detected in d for d in deductions):
            deductions.append(issue.description)
    
    final_score = max(0, score)
    return ScoreBreakdown(
        category="protocol",
        category_name=CATEGORY_NAMES["protocol"],
        score=final_score,
        weight=SCORE_WEIGHTS["protocol"],
        weighted_score=final_score * SCORE_WEIGHTS["protocol"],
        deductions=deductions,
    )


def generate_recommendations(
    chain_validation: ChainValidationResult,
    cipher_security: CipherSecurityResult
) -> List[str]:
    """生成改进建议"""
    recommendations: List[str] = []
    
    # 证书相关建议
    if any(c.is_expired for c in chain_validation.certificates):
        recommendations.append("立即更新已过期的证书")
    elif any(c.is_expiring_soon for c in chain_validation.certificates):
        recommendations.append("尽快更新即将过期的证书")
    
    # 链完整性建议
    if chain_validation.status == "broken":
        recommendations.append("检查证书链配置，确保证书正确签发")
    
    # 加密相关建议
    for issue in cipher_security.issues:
        if issue.recommendation and issue.recommendation not in recommendations:
            recommendations.append(issue.recommendation)
    
    # 协议相关建议
    if not cipher_security.protocol.is_secure and cipher_security.protocol.recommendation:
        if cipher_security.protocol.recommendation not in recommendations:
            recommendations.append(cipher_security.protocol.recommendation)
    
    return recommendations


def check_critical_issues(
    chain_validation: ChainValidationResult,
    cipher_security: CipherSecurityResult
) -> bool:
    """检查是否有严重问题"""
    # 检查是否有过期证书
    if any(c.is_expired for c in chain_validation.certificates):
        return True
    
    # 检查是否有严重或高风险问题
    if cipher_security.overall_risk in ("critical", "high"):
        return True
    
    # 检查链是否断裂
    if chain_validation.status == "broken":
        return True
    
    return False


# ============================================================================
# 核心函数
# ============================================================================

def score_to_grade(score: int, has_critical: bool) -> SecurityGrade:
    """
    将数值分数转换为字母评级
    
    Args:
        score: 数值分数 (0-100)
        has_critical: 是否有严重问题
        
    Returns:
        字母评级
    """
    # 如果有严重问题，评级上限为 C
    max_grade: SecurityGrade = "C" if has_critical else "A+"
    max_grade_index = next(
        (i for i, (_, g) in enumerate(GRADE_THRESHOLDS) if g == max_grade),
        0
    )
    
    for i, (threshold, grade) in enumerate(GRADE_THRESHOLDS):
        if score >= threshold:
            # 如果有严重问题，限制最高评级
            if has_critical and i < max_grade_index:
                return max_grade
            return grade
    
    return "F"


def calculate_security_score(
    chain_validation: ChainValidationResult,
    cipher_security: CipherSecurityResult
) -> SecurityScore:
    """
    计算安全评分
    
    Args:
        chain_validation: 链验证结果
        cipher_security: 加密安全检测结果
        
    Returns:
        安全评分结果
    """
    # 计算各分类分数
    certificate_score = calculate_certificate_score(chain_validation)
    chain_score = calculate_chain_score(chain_validation)
    cipher_score = calculate_cipher_score(cipher_security)
    protocol_score = calculate_protocol_score(cipher_security)
    
    breakdown = [certificate_score, chain_score, cipher_score, protocol_score]
    
    # 计算总分
    numeric_score = round(sum(item.weighted_score for item in breakdown))
    
    # 检查是否有严重问题
    has_critical_issues = check_critical_issues(chain_validation, cipher_security)
    
    # 转换为评级
    grade = score_to_grade(numeric_score, has_critical_issues)
    
    # 生成改进建议
    recommendations = generate_recommendations(chain_validation, cipher_security)
    
    return SecurityScore(
        grade=grade,
        numeric_score=numeric_score,
        breakdown=breakdown,
        has_critical_issues=has_critical_issues,
        recommendations=recommendations,
    )


def get_score_summary(score: SecurityScore) -> str:
    """获取评分的简要摘要"""
    grade_emoji = {
        "A+": "🏆",
        "A": "✅",
        "A-": "✅",
        "B": "🟢",
        "C": "🟡",
        "D": "🟠",
        "F": "🔴",
    }
    
    return f"{grade_emoji[score.grade]} 评级: {score.grade} ({score.numeric_score}/100)"
