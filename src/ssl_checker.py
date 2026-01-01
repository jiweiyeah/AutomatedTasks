"""
SSL 证书检查模块
检查域名的 SSL 证书状态
使用 cryptography 库解析证书，获取与 Node.js 一致的完整信息
包含证书链验证、弱加密检测和安全评分功能
"""
import ssl
import socket
import logging
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional, List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, ExtendedKeyUsageOID

from .config import SSLStatus
from .chain_extractor import (
    CertificateChainInfo,
    extract_certificate_chain,
    get_chain_summary,
)
from .chain_validator import (
    ChainValidationResult,
    validate_chain,
    get_validation_summary,
)
from .weak_cipher_detector import (
    CipherSecurityResult,
    detect_weak_ciphers,
    get_cipher_security_summary,
)
from .security_scorer import (
    SecurityScore,
    calculate_security_score,
    get_score_summary,
)

logger = logging.getLogger(__name__)


@dataclass
class SSLCheckResult:
    """SSL 检查结果 - 与 Next.js NodeSSLCertificateInfo 保持一致"""
    is_valid: bool
    status: str  # valid, expiring, expired, error
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
    bits: Optional[int] = None  # 公钥位数（RSA 2048, ECC 256 等）
    ext_key_usage: Optional[str] = None  # 扩展密钥用法，JSON 数组字符串
    ocsp_uri: Optional[str] = None  # OCSP URL
    ca_issuers_uri: Optional[str] = None  # CA 颁发者 URL
    asn1_curve: Optional[str] = None  # ASN.1 曲线名称（仅 ECC）
    nist_curve: Optional[str] = None  # NIST 曲线名称（仅 ECC）
    error_message: Optional[str] = None


@dataclass
class ExtendedSSLCheckResult(SSLCheckResult):
    """
    扩展的 SSL 检查结果
    包含证书链验证、弱加密检测和安全评分
    与 Next.js ExtendedSSLCertificateInfo 保持一致
    """
    chain_info: Optional[CertificateChainInfo] = None       # 证书链信息
    chain_validation: Optional[ChainValidationResult] = None # 链验证结果
    cipher_security: Optional[CipherSecurityResult] = None   # 加密安全检测结果
    security_score: Optional[SecurityScore] = None           # 安全评分


class SSLCheckError(Exception):
    """SSL 检查失败"""
    def __init__(self, domain: str, message: str):
        self.domain = domain
        self.message = message
        super().__init__(f"SSL 检查失败 [{domain}]: {message}")


def determine_ssl_status(days_remaining: Optional[int], expiring_threshold: int = 30) -> str:
    """
    根据剩余天数判断 SSL 状态
    
    Args:
        days_remaining: 证书剩余天数
        expiring_threshold: 过期预警天数阈值
        
    Returns:
        状态字符串: valid, expiring, expired
    """
    if days_remaining is None:
        return SSLStatus.ERROR
    
    if days_remaining <= 0:
        return SSLStatus.EXPIRED
    elif days_remaining <= expiring_threshold:
        return SSLStatus.EXPIRING
    else:
        return SSLStatus.VALID


# ECC 曲线名称映射（ASN.1 OID -> NIST 名称）
ECC_CURVE_MAPPING = {
    "secp256r1": "P-256",
    "prime256v1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp224r1": "P-224",
    "secp192r1": "P-192",
}


class SSLChecker:
    """SSL 证书检查器"""
    
    def __init__(self, timeout: int = 10, expiring_threshold: int = 30):
        """
        初始化检查器
        
        Args:
            timeout: 连接超时时间（秒）
            expiring_threshold: 过期预警天数
        """
        self.timeout = timeout
        self.expiring_threshold = expiring_threshold
    
    def check(self, domain: str) -> SSLCheckResult:
        """
        检查域名的 SSL 证书
        
        Args:
            domain: 域名（不含协议前缀）
            
        Returns:
            SSL 检查结果
        """
        # 清理域名
        domain = self._clean_domain(domain)
        
        try:
            # 创建 SSL 上下文
            context = ssl.create_default_context()
            
            # 连接并获取证书
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # 获取二进制格式的证书（用于 cryptography 解析）
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()
            
            # 使用 cryptography 解析证书
            return self._parse_certificate_with_cryptography(cert_der, cipher, protocol)
            
        except ssl.SSLCertVerificationError as e:
            logger.warning(f"SSL certificate verification failed [{domain}]: {e}")
            return SSLCheckResult(
                is_valid=False,
                status=SSLStatus.ERROR,
                error_message=f"CERT_VERIFICATION_FAILED:{str(e)}"
            )
        except socket.timeout:
            logger.warning(f"Connection timeout [{domain}]")
            return SSLCheckResult(
                is_valid=False,
                status=SSLStatus.ERROR,
                error_message="CONNECTION_TIMEOUT"
            )
        except socket.gaierror as e:
            logger.warning(f"DNS resolution failed [{domain}]: {e}")
            return SSLCheckResult(
                is_valid=False,
                status=SSLStatus.ERROR,
                error_message=f"DNS_RESOLUTION_FAILED:{str(e)}"
            )
        except ConnectionRefusedError:
            logger.warning(f"Connection refused [{domain}]")
            return SSLCheckResult(
                is_valid=False,
                status=SSLStatus.ERROR,
                error_message="CONNECTION_REFUSED"
            )
        except Exception as e:
            logger.error(f"SSL check error [{domain}]: {e}")
            return SSLCheckResult(
                is_valid=False,
                status=SSLStatus.ERROR,
                error_message=f"UNKNOWN_ERROR:{str(e)}"
            )
    
    def _clean_domain(self, domain: str) -> str:
        """清理域名，移除协议前缀和路径"""
        domain = domain.strip()
        
        # 移除协议前缀
        if domain.startswith("https://"):
            domain = domain[8:]
        elif domain.startswith("http://"):
            domain = domain[7:]
        
        # 移除路径和端口
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        
        return domain

    def _parse_certificate_with_cryptography(
        self, cert_der: bytes, cipher: tuple, protocol: str
    ) -> SSLCheckResult:
        """
        使用 cryptography 库解析证书，获取完整信息
        
        Args:
            cert_der: DER 格式的证书二进制数据
            cipher: 加密套件信息
            protocol: TLS 协议版本
            
        Returns:
            SSL 检查结果
        """
        # 解析证书
        cert = x509.load_der_x509_certificate(cert_der)
        
        # 解析有效期（UTC 时间）
        valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
        valid_to = cert.not_valid_after_utc.replace(tzinfo=None)
        
        # 计算剩余天数（使用 UTC 时间）
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        delta = valid_to - now_utc
        days_remaining = delta.days
        
        # 判断状态
        status = determine_ssl_status(days_remaining, self.expiring_threshold)
        is_valid = status in [SSLStatus.VALID, SSLStatus.EXPIRING]
        
        # 解析颁发者信息
        issuer_cn = self._get_name_attribute(cert.issuer, x509.oid.NameOID.COMMON_NAME)
        issuer_org = self._get_name_attribute(cert.issuer, x509.oid.NameOID.ORGANIZATION_NAME)
        issuer = issuer_cn or issuer_org or "Unknown"
        
        # 计算指纹
        fingerprint_sha1 = self._format_fingerprint(cert.fingerprint(hashes.SHA1()))
        fingerprint_sha256 = self._format_fingerprint(cert.fingerprint(hashes.SHA256()))
        
        # 序列号（十六进制格式，补齐偶数位，与 Node.js 一致）
        hex_serial = format(cert.serial_number, 'X')
        serial_number = ('0' + hex_serial) if len(hex_serial) % 2 == 1 else hex_serial
        
        # 解析公钥信息
        bits, asn1_curve, nist_curve = self._get_public_key_info(cert.public_key())
        
        # 解析 SAN
        subject_alt_names = self._get_subject_alt_names(cert)
        
        # 解析扩展密钥用法
        ext_key_usage = self._get_extended_key_usage(cert)
        
        # 解析 Authority Information Access (OCSP, CA Issuers)
        ocsp_uri, ca_issuers_uri = self._get_authority_info_access(cert)
        
        # 加密套件名称
        cipher_name = cipher[0] if cipher else None
        
        return SSLCheckResult(
            is_valid=is_valid,
            status=status,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            days_remaining=days_remaining,
            protocol=protocol,
            cipher=cipher_name,
            serial_number=serial_number,
            fingerprint=fingerprint_sha1,
            fingerprint_sha256=fingerprint_sha256,
            issuer_org=issuer_org,
            subject_alt_names=subject_alt_names,
            bits=bits,
            ext_key_usage=ext_key_usage,
            ocsp_uri=ocsp_uri,
            ca_issuers_uri=ca_issuers_uri,
            asn1_curve=asn1_curve,
            nist_curve=nist_curve,
        )
    
    def _get_name_attribute(self, name: x509.Name, oid) -> Optional[str]:
        """从 X.509 名称中提取指定属性"""
        try:
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                return attrs[0].value
        except Exception:
            pass
        return None
    
    def _format_fingerprint(self, fingerprint_bytes: bytes) -> str:
        """格式化指纹为冒号分隔的十六进制字符串（与 Node.js 一致）"""
        hex_str = fingerprint_bytes.hex().upper()
        return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    
    def _get_public_key_info(self, public_key) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        获取公钥信息
        
        Returns:
            (bits, asn1_curve, nist_curve)
        """
        bits = None
        asn1_curve = None
        nist_curve = None
        
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                bits = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                bits = public_key.key_size
                curve_name = public_key.curve.name
                asn1_curve = curve_name
                nist_curve = ECC_CURVE_MAPPING.get(curve_name, curve_name)
            elif isinstance(public_key, dsa.DSAPublicKey):
                bits = public_key.key_size
        except Exception as e:
            logger.warning(f"获取公钥信息失败: {e}")
        
        return bits, asn1_curve, nist_curve
    
    def _get_subject_alt_names(self, cert: x509.Certificate) -> Optional[str]:
        """获取 Subject Alternative Names"""
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = ext.value
            names = []
            for name in san:
                if isinstance(name, x509.DNSName):
                    names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    names.append(str(name.value))
            return ", ".join(names) if names else None
        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            logger.warning(f"解析 SAN 失败: {e}")
            return None

    def _get_extended_key_usage(self, cert: x509.Certificate) -> Optional[str]:
        """
        获取扩展密钥用法
        返回 JSON 数组字符串，使用 OID 格式与 Node.js 保持一致
        """
        import json
        
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku = ext.value
            usages = []
            for usage in eku:
                # 使用 OID 的 dotted_string 格式，与 Node.js 保持一致
                usages.append(usage.dotted_string)
            return json.dumps(usages) if usages else None
        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            logger.warning(f"解析扩展密钥用法失败: {e}")
            return None
    
    def _get_authority_info_access(self, cert: x509.Certificate) -> Tuple[Optional[str], Optional[str]]:
        """
        获取 Authority Information Access 扩展
        
        Returns:
            (ocsp_uri, ca_issuers_uri)
        """
        ocsp_uri = None
        ca_issuers_uri = None
        
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia = ext.value
            
            for access_description in aia:
                if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_description.access_location, x509.UniformResourceIdentifier):
                        ocsp_uri = access_description.access_location.value
                elif access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(access_description.access_location, x509.UniformResourceIdentifier):
                        ca_issuers_uri = access_description.access_location.value
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.warning(f"解析 AIA 失败: {e}")
        
        return ocsp_uri, ca_issuers_uri

    def check_extended(self, domain: str) -> ExtendedSSLCheckResult:
        """
        扩展的 SSL 证书检查
        包含证书链验证、弱加密检测和安全评分
        与 Next.js getExtendedSSLCertificate 保持一致
        
        Args:
            domain: 域名（不含协议前缀）
            
        Returns:
            扩展的 SSL 检查结果
        """
        # 清理域名
        domain = self._clean_domain(domain)
        
        # 先执行基础检查
        basic_result = self.check(domain)
        
        # 如果基础检查失败，返回带有空安全信息的结果
        if basic_result.status == SSLStatus.ERROR:
            return ExtendedSSLCheckResult(
                is_valid=basic_result.is_valid,
                status=basic_result.status,
                issuer=basic_result.issuer,
                valid_from=basic_result.valid_from,
                valid_to=basic_result.valid_to,
                days_remaining=basic_result.days_remaining,
                protocol=basic_result.protocol,
                cipher=basic_result.cipher,
                serial_number=basic_result.serial_number,
                fingerprint=basic_result.fingerprint,
                fingerprint_sha256=basic_result.fingerprint_sha256,
                issuer_org=basic_result.issuer_org,
                subject_alt_names=basic_result.subject_alt_names,
                bits=basic_result.bits,
                ext_key_usage=basic_result.ext_key_usage,
                ocsp_uri=basic_result.ocsp_uri,
                ca_issuers_uri=basic_result.ca_issuers_uri,
                asn1_curve=basic_result.asn1_curve,
                nist_curve=basic_result.nist_curve,
                error_message=basic_result.error_message,
                chain_info=None,
                chain_validation=None,
                cipher_security=None,
                security_score=None,
            )
        
        try:
            # 1. 提取证书链
            chain_info = extract_certificate_chain(domain, self.timeout)
            logger.debug(f"证书链: {get_chain_summary(chain_info)}")
            
            # 2. 验证证书链
            chain_validation = validate_chain(chain_info)
            logger.debug(f"链验证: {get_validation_summary(chain_validation)}")
            
            # 3. 检测弱加密
            cipher_security = detect_weak_ciphers(
                chain_info,
                basic_result.protocol or "",
                basic_result.cipher or ""
            )
            logger.debug(f"加密安全: {get_cipher_security_summary(cipher_security)}")
            
            # 4. 计算安全评分
            security_score = calculate_security_score(chain_validation, cipher_security)
            logger.debug(f"安全评分: {get_score_summary(security_score)}")
            
            return ExtendedSSLCheckResult(
                is_valid=basic_result.is_valid,
                status=basic_result.status,
                issuer=basic_result.issuer,
                valid_from=basic_result.valid_from,
                valid_to=basic_result.valid_to,
                days_remaining=basic_result.days_remaining,
                protocol=basic_result.protocol,
                cipher=basic_result.cipher,
                serial_number=basic_result.serial_number,
                fingerprint=basic_result.fingerprint,
                fingerprint_sha256=basic_result.fingerprint_sha256,
                issuer_org=basic_result.issuer_org,
                subject_alt_names=basic_result.subject_alt_names,
                bits=basic_result.bits,
                ext_key_usage=basic_result.ext_key_usage,
                ocsp_uri=basic_result.ocsp_uri,
                ca_issuers_uri=basic_result.ca_issuers_uri,
                asn1_curve=basic_result.asn1_curve,
                nist_curve=basic_result.nist_curve,
                error_message=basic_result.error_message,
                chain_info=chain_info,
                chain_validation=chain_validation,
                cipher_security=cipher_security,
                security_score=security_score,
            )
            
        except Exception as e:
            logger.warning(f"扩展检查失败 [{domain}]: {e}")
            # 返回基础结果，安全信息为空
            return ExtendedSSLCheckResult(
                is_valid=basic_result.is_valid,
                status=basic_result.status,
                issuer=basic_result.issuer,
                valid_from=basic_result.valid_from,
                valid_to=basic_result.valid_to,
                days_remaining=basic_result.days_remaining,
                protocol=basic_result.protocol,
                cipher=basic_result.cipher,
                serial_number=basic_result.serial_number,
                fingerprint=basic_result.fingerprint,
                fingerprint_sha256=basic_result.fingerprint_sha256,
                issuer_org=basic_result.issuer_org,
                subject_alt_names=basic_result.subject_alt_names,
                bits=basic_result.bits,
                ext_key_usage=basic_result.ext_key_usage,
                ocsp_uri=basic_result.ocsp_uri,
                ca_issuers_uri=basic_result.ca_issuers_uri,
                asn1_curve=basic_result.asn1_curve,
                nist_curve=basic_result.nist_curve,
                error_message=basic_result.error_message,
                chain_info=None,
                chain_validation=None,
                cipher_security=None,
                security_score=None,
            )
