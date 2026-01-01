"""
证书链提取器模块
负责从 TLS 连接中提取完整的证书链信息
与 Next.js lib/ssl/chain-extractor.ts 保持一致

关键差异说明：
- Node.js 的 getPeerCertificate(true) 会通过 issuerCertificate 链式遍历
  并自动从系统信任库补全根证书
- Python 的标准 ssl 模块（特别是 macOS 的 LibreSSL）不支持获取完整证书链
- 本模块使用 openssl s_client 命令获取服务器发送的证书链，
  然后使用 certifi 提供的 CA 证书库来补全根证书，保持与 Node.js 一致
"""
import ssl
import socket
import logging
import certifi
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional, List, Literal, Dict
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# ============================================================================
# 类型定义
# ============================================================================

# 证书类型
CertificateType = Literal["leaf", "intermediate", "root"]


@dataclass
class CertificateSubject:
    """证书主题/颁发者信息"""
    CN: Optional[str] = None  # Common Name - 通用名称
    O: Optional[str] = None   # Organization - 组织
    OU: Optional[str] = None  # Organizational Unit - 组织单位
    C: Optional[str] = None   # Country - 国家


@dataclass
class ChainCertificate:
    """单个证书信息"""
    type: CertificateType                    # 证书类型
    subject: CertificateSubject              # 证书主题 (Subject)
    issuer: CertificateSubject               # 证书颁发者 (Issuer)
    valid_from: str                          # 有效期开始 (ISO String)
    valid_to: str                            # 有效期结束 (ISO String)
    days_remaining: int                      # 剩余天数
    serial_number: str                       # 序列号
    signature_algorithm: Optional[str] = None  # 签名算法
    public_key_algorithm: Optional[str] = None # 公钥算法
    key_bits: Optional[int] = None           # 密钥长度 (bits)
    is_self_signed: bool = False             # 是否自签名
    fingerprint_sha256: Optional[str] = None # SHA-256 指纹


@dataclass
class InferredRoot:
    """推断的根证书信息"""
    name: str                                # 根证书名称
    organization: Optional[str] = None       # 组织名称
    trusted: bool = False                    # 是否受系统信任


@dataclass
class CertificateChainInfo:
    """证书链信息"""
    chain: List[ChainCertificate] = field(default_factory=list)  # 证书链数组
    chain_length: int = 0                    # 链长度
    is_complete: bool = False                # 链是否完整
    root_trusted: bool = False               # 根证书是否受信任
    inferred_root: Optional[InferredRoot] = None  # 推断的根证书信息


# ============================================================================
# 全局缓存：CA 证书库
# ============================================================================

_ca_certs_cache: Optional[Dict[str, x509.Certificate]] = None


def _load_ca_certs() -> Dict[str, x509.Certificate]:
    """
    加载 certifi 提供的 CA 证书库
    使用 Subject 的字符串表示作为 key，方便查找
    """
    global _ca_certs_cache
    if _ca_certs_cache is not None:
        return _ca_certs_cache
    
    _ca_certs_cache = {}
    try:
        with open(certifi.where(), 'rb') as f:
            pem_data = f.read()
        
        # 解析 PEM 格式的证书（可能包含多个证书）
        # 使用简单的分割方式
        pem_certs = pem_data.split(b'-----END CERTIFICATE-----')
        for pem_cert in pem_certs:
            pem_cert = pem_cert.strip()
            if not pem_cert:
                continue
            # 补回结束标记
            pem_cert = pem_cert + b'\n-----END CERTIFICATE-----\n'
            try:
                cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                # 使用 Subject 的 RFC4514 字符串作为 key
                subject_key = cert.subject.rfc4514_string()
                _ca_certs_cache[subject_key] = cert
            except Exception:
                continue
        
        logger.debug(f"加载了 {len(_ca_certs_cache)} 个 CA 证书")
    except Exception as e:
        logger.warning(f"加载 CA 证书库失败: {e}")
        _ca_certs_cache = {}
    
    return _ca_certs_cache


def _find_issuer_cert(issuer: x509.Name) -> Optional[x509.Certificate]:
    """
    从 CA 证书库中查找颁发者证书
    """
    ca_certs = _load_ca_certs()
    issuer_key = issuer.rfc4514_string()
    return ca_certs.get(issuer_key)


# ============================================================================
# 工具函数
# ============================================================================

def calculate_days_remaining(valid_to: datetime) -> int:
    """计算剩余天数"""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if valid_to.tzinfo:
        valid_to = valid_to.replace(tzinfo=None)
    delta = valid_to - now
    return delta.days


def is_self_signed_cert(subject: CertificateSubject, issuer: CertificateSubject) -> bool:
    """判断证书是否为自签名"""
    return (
        subject.CN == issuer.CN and
        subject.O == issuer.O and
        subject.C == issuer.C
    )


def format_fingerprint(fingerprint_bytes: bytes) -> str:
    """格式化指纹为冒号分隔的十六进制字符串"""
    hex_str = fingerprint_bytes.hex().upper()
    return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


def get_name_attribute(name: x509.Name, oid) -> Optional[str]:
    """从 X.509 名称中提取指定属性"""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return None


def parse_subject(name: x509.Name) -> CertificateSubject:
    """解析证书主题/颁发者信息"""
    return CertificateSubject(
        CN=get_name_attribute(name, x509.oid.NameOID.COMMON_NAME),
        O=get_name_attribute(name, x509.oid.NameOID.ORGANIZATION_NAME),
        OU=get_name_attribute(name, x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME),
        C=get_name_attribute(name, x509.oid.NameOID.COUNTRY_NAME),
    )


def get_signature_algorithm(cert: x509.Certificate) -> Optional[str]:
    """获取签名算法名称"""
    try:
        return cert.signature_algorithm_oid._name
    except Exception:
        try:
            return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except Exception:
            return None


def get_public_key_info(public_key) -> tuple:
    """获取公钥信息 (bits, algorithm)"""
    bits = None
    algorithm = None
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            bits = public_key.key_size
            algorithm = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            bits = public_key.key_size
            algorithm = f"EC ({public_key.curve.name})"
        elif isinstance(public_key, dsa.DSAPublicKey):
            bits = public_key.key_size
            algorithm = "DSA"
    except Exception as e:
        logger.warning(f"获取公钥信息失败: {e}")
    
    return bits, algorithm


def _parse_cert_to_chain_cert(cert: x509.Certificate, cert_type: CertificateType) -> ChainCertificate:
    """将 x509.Certificate 解析为 ChainCertificate"""
    subject = parse_subject(cert.subject)
    issuer = parse_subject(cert.issuer)
    
    # 解析有效期 - 兼容不同 Python 版本
    try:
        valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
        valid_to = cert.not_valid_after_utc.replace(tzinfo=None)
    except AttributeError:
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after
        if valid_from.tzinfo:
            valid_from = valid_from.replace(tzinfo=None)
        if valid_to.tzinfo:
            valid_to = valid_to.replace(tzinfo=None)
    
    days_remaining = calculate_days_remaining(valid_to)
    is_self_signed = is_self_signed_cert(subject, issuer)
    key_bits, pub_key_algo = get_public_key_info(cert.public_key())
    
    hex_serial = format(cert.serial_number, 'X')
    serial_number = ('0' + hex_serial) if len(hex_serial) % 2 == 1 else hex_serial
    fingerprint_sha256 = format_fingerprint(cert.fingerprint(hashes.SHA256()))
    
    return ChainCertificate(
        type=cert_type,
        subject=subject,
        issuer=issuer,
        valid_from=valid_from.isoformat(),
        valid_to=valid_to.isoformat(),
        days_remaining=days_remaining,
        serial_number=serial_number,
        signature_algorithm=get_signature_algorithm(cert),
        public_key_algorithm=pub_key_algo,
        key_bits=key_bits,
        is_self_signed=is_self_signed,
        fingerprint_sha256=fingerprint_sha256,
    )


# ============================================================================
# 核心函数
# ============================================================================

def _get_certs_via_openssl(domain: str, timeout: int = 10) -> List[x509.Certificate]:
    """
    使用 openssl s_client 命令获取服务器发送的完整证书链
    这是最可靠的方式，因为 Python ssl 模块在某些平台上不支持获取完整链
    """
    certs = []
    try:
        # 使用 openssl s_client 获取证书链
        cmd = f"echo | openssl s_client -connect {domain}:443 -showcerts 2>/dev/null"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            return []
        
        # 解析 PEM 格式的证书
        output = result.stdout
        cert_pattern = re.compile(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            re.DOTALL
        )
        
        pem_certs = cert_pattern.findall(output)
        for pem_cert in pem_certs:
            try:
                cert = x509.load_pem_x509_certificate(
                    pem_cert.encode(), 
                    default_backend()
                )
                certs.append(cert)
            except Exception as e:
                logger.warning(f"解析证书失败: {e}")
                continue
        
        logger.debug(f"[{domain}] openssl 获取到 {len(certs)} 个证书")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"[{domain}] openssl 命令超时")
    except Exception as e:
        logger.warning(f"[{domain}] openssl 命令失败: {e}")
    
    return certs


def _get_certs_via_ssl(domain: str, timeout: int = 10) -> tuple:
    """
    使用 Python ssl 模块获取证书（回退方案）
    返回 (certs, root_trusted)
    """
    certs = []
    root_trusted = False
    
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # 尝试 get_verified_chain (Python 3.10+ with OpenSSL)
                if hasattr(ssock, 'get_verified_chain'):
                    try:
                        cert_chain_der = ssock.get_verified_chain()
                        if cert_chain_der:
                            for cert_der in cert_chain_der:
                                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                                certs.append(cert)
                            root_trusted = True
                            return certs, root_trusted
                    except Exception:
                        pass
                
                # 回退：只获取叶子证书
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    certs.append(cert)
                    root_trusted = True
                    
    except ssl.SSLCertVerificationError:
        # 证书验证失败
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        certs.append(cert)
        except Exception:
            pass
            
    except Exception as e:
        logger.debug(f"[{domain}] ssl 模块获取证书失败: {e}")
    
    return certs, root_trusted


def extract_certificate_chain(
    domain: str,
    timeout: int = 10
) -> CertificateChainInfo:
    """
    从 TLS 连接提取完整证书链
    
    与 Node.js 保持一致：
    - Node.js 的 getPeerCertificate(true) 会通过 issuerCertificate 链式遍历
      并自动从系统信任库补全根证书
    - 本函数优先使用 openssl 命令获取服务器发送的证书链
    - 然后使用 certifi 提供的 CA 证书库来补全根证书
    
    Args:
        domain: 域名
        timeout: 连接超时时间
        
    Returns:
        证书链信息
    """
    chain: List[ChainCertificate] = []
    root_trusted = False
    server_certs: List[x509.Certificate] = []
    
    # 方法1：使用 openssl 命令获取完整证书链（推荐）
    server_certs = _get_certs_via_openssl(domain, timeout)
    
    # 方法2：回退到 Python ssl 模块
    if not server_certs:
        server_certs, root_trusted = _get_certs_via_ssl(domain, timeout)
    else:
        # openssl 成功获取证书，验证是否受信任
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    root_trusted = True
        except ssl.SSLCertVerificationError:
            root_trusted = False
        except Exception:
            root_trusted = True  # 假设受信任
    
    if not server_certs:
        return CertificateChainInfo()
    
    # 构建证书链
    visited_fingerprints = set()
    
    for index, cert in enumerate(server_certs):
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        if fingerprint in visited_fingerprints:
            continue
        visited_fingerprints.add(fingerprint)
        
        subject = parse_subject(cert.subject)
        issuer = parse_subject(cert.issuer)
        is_self_signed = is_self_signed_cert(subject, issuer)
        
        # 判断证书类型
        if index == 0:
            cert_type: CertificateType = "leaf"
        elif is_self_signed:
            cert_type = "root"
        else:
            cert_type = "intermediate"
        
        chain_cert = _parse_cert_to_chain_cert(cert, cert_type)
        chain.append(chain_cert)
        
        if is_self_signed:
            break
    
    # 如果链不完整（最后一个证书不是自签名），尝试从 CA 库补全根证书
    last_cert = server_certs[-1] if server_certs else None
    if last_cert:
        last_subject = parse_subject(last_cert.subject)
        last_issuer = parse_subject(last_cert.issuer)
        
        if not is_self_signed_cert(last_subject, last_issuer):
            current_cert = last_cert
            max_depth = 5
            
            for _ in range(max_depth):
                issuer_cert = _find_issuer_cert(current_cert.issuer)
                if not issuer_cert:
                    break
                
                fingerprint = issuer_cert.fingerprint(hashes.SHA256()).hex()
                if fingerprint in visited_fingerprints:
                    break
                visited_fingerprints.add(fingerprint)
                
                issuer_subject = parse_subject(issuer_cert.subject)
                issuer_issuer = parse_subject(issuer_cert.issuer)
                is_self_signed = is_self_signed_cert(issuer_subject, issuer_issuer)
                
                cert_type = "root" if is_self_signed else "intermediate"
                chain_cert = _parse_cert_to_chain_cert(issuer_cert, cert_type)
                chain.append(chain_cert)
                
                if is_self_signed:
                    break
                
                current_cert = issuer_cert
    
    # 判断链是否完整
    final_cert = chain[-1] if chain else None
    is_complete = final_cert.is_self_signed if final_cert else False
    
    # 如果链不完整但受信任，推断根证书信息
    inferred_root = None
    if not is_complete and final_cert and root_trusted:
        inferred_root = InferredRoot(
            name=final_cert.issuer.CN or final_cert.issuer.O or "Unknown Root CA",
            organization=final_cert.issuer.O,
            trusted=True,
        )
    
    return CertificateChainInfo(
        chain=chain,
        chain_length=len(chain),
        is_complete=is_complete,
        root_trusted=root_trusted,
        inferred_root=inferred_root,
    )


def get_chain_summary(chain_info: CertificateChainInfo) -> str:
    """获取证书链的简要描述"""
    if chain_info.chain_length == 0:
        return "No certificate chain available"
    
    parts = []
    for index, cert in enumerate(chain_info.chain):
        name = cert.subject.CN or cert.subject.O or "Unknown"
        parts.append(f"[{index}] {cert.type}: {name}")
    
    return " → ".join(parts)
