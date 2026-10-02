"""
JA3 / JA4 客户端指纹 —— 追溯类能力

背景:
  JA3 通过 TLS ClientHello 中的一组字段（SSL 版本、密码套件、扩展、椭圆曲线、曲线点格式）
  生成固定的 MD5 指纹，能稳定标识一个 TLS 客户端实现（curl、python-requests、浏览器、 Scanner）。
  即使攻击者换 IP、改 UA，只要底层 TLS 栈不变，JA3 仍可关联同一攻击者。JA4 是 2023 年
  推出的改进版（可读字符串，区分握手类型/版本/密码套件前缀/扩展哈希/曲线哈希）。

现实约束:
  本项目通常作为反向代理后端的 Web 应用，自身不终止 TLS，拿不到原始 ClientHello。
  因此本模块按优先级处理：
    1) 若前端代理（nginx/HAProxy/Cloudflare）已算出 JA3/JA4 并通过请求头透传，则直接采用；
    2) 否则退回到「合成指纹」：用请求中能看到的、与 TLS 栈强相关的稳定信号（HTTP 版本、
       ALPN/协议、关键请求头顺序、User-Agent 等）算一个哈希，作为 JA3 的近似替代。
       合成指纹在模块内明确标记为 synthetic=True，不能与真实 JA3 混为一谈。

无论来源如何，所有指纹都会登记到 ja3_fingerprints 表，并对「首次出现的陌生指纹」告警，
从而支撑跨 IP/账号的攻击者关联与追溯。
"""
import hashlib
import logging

from . import configs
from .core_db import async_db_query, _get_conn
from .security import record_security_event

logger = logging.getLogger("ja3")

# 内存级已见指纹缓存：同一指纹只落库/告警一次，避免每个请求都写库。
_seen_cache = set()


# ===========================================================================
# 标准 JA3 算法
# ===========================================================================
def compute_ja3_hash(ssl_version: str, ciphers: list, extensions: list,
                     curves: list, ec_point_formats: list) -> str:
    """给定 ClientHello 五元组，按标准 JA3 算法计算 MD5。

    JA3 字符串格式: "SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
    其中每项以 '-' 连接各整数/值。空列表用空字符串表示。
    """
    def join_vals(vals):
        return "-".join(str(v) for v in (vals or []))
    ja3_str = ",".join([
        str(ssl_version or ""),
        join_vals(ciphers),
        join_vals(extensions),
        join_vals(curves),
        join_vals(ec_point_formats),
    ])
    return hashlib.md5(ja3_str.encode("utf-8")).hexdigest()


def parse_ja3_string(ja3_str: str):
    """解析 "v,ciphers,exts,curves,ecfmt" 形式的 JA3 字符串为字段并重新 hash，用于校验。"""
    parts = (ja3_str or "").split(",")
    if len(parts) != 5:
        return None
    try:
        def to_list(s):
            return [int(x) for x in s.split("-") if x != ""] if s else []
        ssl_version = parts[0]
        ciphers = to_list(parts[1])
        extensions = to_list(parts[2])
        curves = to_list(parts[3])
        ec_point_formats = to_list(parts[4])
        return compute_ja3_hash(ssl_version, ciphers, extensions, curves, ec_point_formats)
    except Exception:
        return None


# ===========================================================================
# 从请求提取 JA3（代理头优先，否则合成）
# ===========================================================================
# 来源优先级（高 → 低）：Cloudflare 边缘 > 自定义反代 > 合成兜底
#
# Cloudflare（Enterprise + Bot Management 开启 "Add bot protection headers" Managed Transform
# 后，会把这些头加到发往源站的请求里）：
#   cf-ja3-hash   —— JA3 的 MD5（32 位 hex），最可信
#   cf-ja3n-hash  —— JA3N（带 SNI 的变体）MD5
#   cf-ja4        —— 完整 JA4 字符串（如 t13d1516h2_8daaf6152771df4e_02713eb1ec9d5928）
# 这些来自 Cloudflare 边缘、基于真实 ClientHello 计算，不可被终端用户伪造（不像普通请求头）。
_CLOUDFLARE_JA3_HEADERS = ["cf-ja3-hash", "cf-ja3n-hash"]
_CLOUDFLARE_JA4_HEADER = "cf-ja4"

# 其它反代 / 自托管边缘可能透传的头（大小写不敏感匹配由下方 _hdr 完成）
_PROXY_JA3_TUPLE_HEADERS = ["x-ja3-raw", "x-ja3"]           # 原始 JA3 元组，解析后重新 hash（自带校验）
_PROXY_JA3_HASH_HEADERS = ["x-ja3-fingerprint", "x-ssl-ja3", "x-tls-ja3", "x-ja3-hash"]
_PROXY_JA4_HEADERS = ["x-ja4-fingerprint", "ja4", "x-ja4"]


def _hdr(req, name):
    return req.headers.get(name, req.headers.get(name.replace("-", "_").upper(), ""))


def _extract_ja4(req):
    # Cloudflare 优先（cf-ja4 是完整字符串），其次其它代理头
    for h in [_CLOUDFLARE_JA4_HEADER] + _PROXY_JA4_HEADERS:
        v = _hdr(req, h)
        if v:
            return v.strip()
    return ""


def _synthetic_ja3(req, client_ip):
    """无 TLS 可见性时，用稳定请求信号合成近似指纹。"""
    parts = []
    # HTTP 协议版本（2/1.1/1.0）——与 TLS ALPN 强相关
    ver = getattr(req, "http_version", "") or ""
    parts.append("h" + (ver.replace(".", "") or "?"))
    # 关键请求头（顺序敏感，作为信号）
    for h in ("user-agent", "accept", "accept-language", "accept-encoding",
              "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile"):
        val = _hdr(req, h)
        if val:
            # 只取前 64 字符，避免超长 UA 造成指纹抖动；头名+截断值参与哈希
            parts.append(f"{h}={val[:64]}")
    raw = "|".join(parts)
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return "syn-" + h


def extract_ja3(req, client_ip: str = "") -> dict:
    """从请求提取 JA3/JA4 信息。

    来源优先级（高 → 低）：
      cloudflare > header（自定义反代透传）> synthetic（无 TLS 可见性时合成）

    返回 dict:
      ja3_hash, ja4, source('cloudflare'|'header'|'synthetic'), synthetic(bool),
      raw(str|'')
    """
    if not getattr(configs, "JA3_ENABLED", True):
        return {"enabled": False}

    ja3_hash = ""
    ja3_raw = ""
    source = "synthetic"
    synthetic = True

    # 1) Cloudflare 边缘透传的真实 JA3（边缘计算、握手阶段产生，无法被终端用户伪造）。
    #    cf-* 头始终作为真实 JA3 哈希识别；JA3_TRUST_CLOUDFLARE 仅控制来源标签
    #    （cloudflare / header），不信任时也不丢弃真实指纹。
    trust_cf = getattr(configs, "JA3_TRUST_CLOUDFLARE", True)
    for h in _CLOUDFLARE_JA3_HEADERS:
        v = _hdr(req, h)
        if v:
            cand = v.strip().lower()
            if len(cand) == 32 and all(c in "0123456789abcdef" for c in cand):
                ja3_hash = cand
                source = "cloudflare" if trust_cf else "header"
                synthetic = False
                break

    # 2) 其它反代透传的原始 JA3 元组（解析后重新 hash，自带校验）
    if not ja3_hash:
        for h in _PROXY_JA3_TUPLE_HEADERS:
            v = _hdr(req, h)
            if v:
                computed = parse_ja3_string(v.strip())
                if computed:
                    ja3_hash = computed
                    ja3_raw = v.strip()
                    source = "header"
                    synthetic = False
                    break

    # 3) 其它反代透传的 JA3 哈希
    if not ja3_hash:
        for h in _PROXY_JA3_HASH_HEADERS:
            v = _hdr(req, h)
            if v:
                cand = v.strip().lower()
                if len(cand) == 32 and all(c in "0123456789abcdef" for c in cand):
                    ja3_hash = cand
                    source = "header"
                    synthetic = False
                    break

    # 4) JA4：Cloudflare 优先，其次其它代理头（JA4 为完整字符串，原样保留）
    #    注意：JA4 是独立字段；若 JA3 缺失（理论上 CF 会同时给出），仍按合成 JA3 处理，不伪装成真实。
    ja4 = _extract_ja4(req)

    # 5) 兜底合成：无任何真实 JA3 可见性时，用稳定请求信号合成近似指纹
    if not ja3_hash and getattr(configs, "JA3_SYNTHETIC_FALLBACK", True):
        ja3_hash = _synthetic_ja3(req, client_ip)
        source = "synthetic"
        synthetic = True

    return {
        "ja3_hash": ja3_hash,
        "ja4": ja4,
        "source": source,
        "synthetic": synthetic,
        "raw": ja3_raw,
    }


# ===========================================================================
# 指纹登记与告警
# ===========================================================================
async def register_fingerprint_async(ja3: dict, client_ip: str, user_agent: str,
                                     user_uid: str = "", user_name: str = ""):
    """登记一个指纹：写入/更新 ja3_fingerprints，并对陌生指纹告警。

    返回 (is_new, info)。
    """
    if not getattr(configs, "JA3_ENABLED", True):
        return (False, {})
    h = ja3.get("ja3_hash")
    if not h:
        return (False, {})
    # 内存去重：已见过的指纹不再写库/告警（计数近似即可）
    if h in _seen_cache:
        return (False, {"hash": h, "cached": True})
    try:
        rows = await async_db_query(
            "SELECT hash, seen_count, is_flagged FROM ja3_fingerprints WHERE hash=?",
            (h,)
        )
        is_new = not bool(rows)
        if is_new:
            _seen_cache.add(h)
            await async_db_query(
                """INSERT INTO ja3_fingerprints
                   (hash, ja4, first_seen, last_seen, seen_count, ua_samples, ip_samples,
                    is_flagged, note)
                   VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?, ?, ?)""",
                (h, ja3.get("ja4", ""),
                 (user_agent or "")[:200], (client_ip or "")[:64],
                 1 if getattr(configs, "JA3_FLAG_NOVEL", True) else 0,
                 "synthetic" if ja3.get("synthetic") else "novel-fp")
            )
            # 陌生指纹告警（仅当启用告警且非合成指纹时强提醒；合成指纹仅记录）
            if getattr(configs, "JA3_FLAG_NOVEL", True):
                try:
                    from .security import DeviceInfo
                    dev = DeviceInfo("unknown", "Unknown", "", "", "", "",
                                     False, [], user_agent or "")
                    await record_security_event(
                        async_db_query, user_uid, user_name,
                        "ja3_novel", "warn", 20,
                        [f"首次出现的 JA3 指纹: {h}",
                         f"来源: {ja3.get('source')}", f"IP: {client_ip}"],
                        client_ip, dev, action_taken="monitored"
                    )
                except Exception as e:
                    logger.debug(f"ja3 novel alert failed: {e}")
        else:
            # 更新计数与样本
            await async_db_query(
                """UPDATE ja3_fingerprints
                   SET last_seen=CURRENT_TIMESTAMP, seen_count=seen_count+1,
                       ua_samples=?, ip_samples=?, ja4=COALESCE(NULLIF(?, ''), ja4)
                   WHERE hash=?""",
                ((user_agent or "")[:200], (client_ip or "")[:64],
                 ja3.get("ja4", "") or "", h)
            )
        return (is_new, {"hash": h, "source": ja3.get("source"), "synthetic": ja3.get("synthetic")})
    except Exception as e:
        logger.error(f"register_fingerprint failed: {e}")
        return (False, {"error": str(e)})


def list_fingerprints(limit: int = 50, only_flagged: bool = False):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        sql = ("SELECT hash, ja4, first_seen, last_seen, seen_count, is_flagged, note "
               "FROM ja3_fingerprints")
        if only_flagged:
            sql += " WHERE is_flagged=1"
        sql += " ORDER BY seen_count DESC LIMIT ?"
        cur.execute(sql, (limit,))
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"list_fingerprints failed: {e}")
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def status() -> dict:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c, SUM(is_flagged) AS f FROM ja3_fingerprints")
        row = cur.fetchone()
        return {
            "enabled": getattr(configs, "JA3_ENABLED", True),
            "total": row["c"] if row else 0,
            "flagged": row["f"] if row and row["f"] else 0,
            "synthetic_fallback": getattr(configs, "JA3_SYNTHETIC_FALLBACK", True),
            "flag_novel": getattr(configs, "JA3_FLAG_NOVEL", True),
            "trust_cloudflare": getattr(configs, "JA3_TRUST_CLOUDFLARE", True),
        }
    except Exception:
        return {"enabled": getattr(configs, "JA3_ENABLED", True), "total": 0, "flagged": 0}
    finally:
        try:
            conn.close()
        except Exception:
            pass
