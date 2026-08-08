#!/usr/bin/env python3
"""
演出票务 MCP Server (带数据保护)
===================================
在原始 MCP 工具基础上增加：
  1. 隐形数字水印 — 每个调用者的响应中嵌入不可见但可溯源的 Unicode 零宽字符指纹
  2. 结构化调用日志 — JSON Lines 格式，记录调用者 IP/UA/工具/参数/时间戳
  3. 价格微水印 — 对数值字段施加 ±0.01 的 caller-specific 偏移，便于大数据级溯源

命令行参数 (按顺序):
  sys.argv[1]  result_mode (display_only / no_reply)
  sys.argv[2]  api_base_url  后端 API 基础 URL
  sys.argv[3]  host          监听地址
  sys.argv[4]  port          监听端口
  sys.argv[5]  sse_path      SSE 端点路径

使用方式:
  python ticket_mcp_server_protected.py display_only http://127.0.0.1:3000 0.0.0.0 8000 /sse
"""

import sys
import os
import json
import hashlib
import uuid
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

# ============================================================================
# 零宽字符水印编码表 (不可见、不影响文本显示，但可被程序检测)
# ============================================================================
ZW_ZERO = "\u200B"  # Zero Width Space
ZW_ONE  = "\u200C"  # Zero Width Non-Joiner
ZW_SEP  = "\uFEFF"  # Zero Width No-Break Space (分隔符)

# ============================================================================
# 水印管理器
# ============================================================================
class WatermarkManager:
    """为每个调用者生成唯一不可见指纹，并注入响应文本中。"""

    def __init__(self, secret: str = "pianam-mcp-2026"):
        self.secret = secret

    def client_fingerprint(self, ip: str, user_agent: str = "") -> str:
        """根据调用者 IP + UA 生成 16 位 hex 指纹。"""
        raw = f"{self.secret}|{ip}|{user_agent}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def encode_fingerprint(self, fp_hex: str) -> str:
        """将 hex 指纹编码为零宽字符序列。"""
        bits = ""
        for ch in fp_hex:
            bits += format(int(ch, 16), "04b")
        return "".join(ZW_ZERO if b == "0" else ZW_ONE for b in bits) + ZW_SEP

    def inject(self, text: str, fingerprint: str) -> str:
        """在文本的 ~20% 位置注入水印（不影响可读性）。"""
        if not text or not isinstance(text, str):
            return text
        wm = self.encode_fingerprint(fingerprint)
        pos = max(1, len(text) // 5)
        return text[:pos] + wm + text[pos:]

    def inject_prices(self, val: Optional[float], fingerprint: str) -> Optional[float]:
        """对价格施加 ±0.01 的确定性偏移（可用于大数据级溯源）。"""
        if val is None:
            return None
        # 用指纹后 4 位做 seed，确保同一调用者同一价格偏移一致
        seed = int(fingerprint[-4:], 16)
        offset = 0.01 if seed % 2 == 0 else -0.01
        return round(val + offset, 2)

    def verify(self, text: str) -> Optional[str]:
        """从文本中提取水印指纹（用于维权取证）。"""
        if not text or not isinstance(text, str):
            return None
        # 提取所有零宽字符
        bits = ""
        for ch in text:
            if ch == ZW_ZERO:
                bits += "0"
            elif ch == ZW_ONE:
                bits += "1"
            elif ch == ZW_SEP:
                if len(bits) >= 16 and len(bits) % 4 == 0:
                    hex_str = ""
                    for i in range(0, len(bits), 4):
                        hex_str += format(int(bits[i:i+4], 2), "x")
                    return hex_str
                bits = ""
        return None


# ============================================================================
# 调用日志记录器
# ============================================================================
class CallLogger:
    """JSON Lines 格式结构化日志，便于分析和取证。"""

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "mcp_access.log"
        self.alert_file = self.log_dir / "mcp_alerts.log"

    def log_call(self, client_ip: str, user_agent: str, fingerprint: str,
                 tool_name: str, params: dict, response_size: int,
                 duration_ms: float, session_id: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "user_agent": user_agent[:200],
            "fingerprint": fingerprint,
            "session_id": session_id,
            "tool": tool_name,
            "params": {k: v for k, v in params.items() if v is not None},
            "response_size": response_size,
            "duration_ms": round(duration_ms, 1),
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def log_alert(self, alert_type: str, detail: dict):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "detail": detail,
        }
        with open(self.alert_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get_stats(self) -> dict:
        """获取日志统计摘要。"""
        if not self.log_file.exists():
            return {"total_calls": 0, "unique_clients": 0}
        ips = set()
        count = 0
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    ips.add(entry.get("client_ip", ""))
                    count += 1
                except:
                    pass
        return {"total_calls": count, "unique_clients": len(ips)}


# ============================================================================
# 后端 API 客户端 (与原版一致)
# ============================================================================
class TicketApiClient:

    def __init__(self, base_url: str, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()

    def _get(self, path: str, params: Optional[dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.get(url, params=params, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            raise RuntimeError(f"API 请求失败 [{url}]: {e}") from e
        except ValueError as e:
            raise RuntimeError(f"API 返回非 JSON [{url}]: {e}") from e
        if isinstance(data, dict) and data.get("code") not in (0, 200, None):
            raise RuntimeError(
                f"API 业务错误 code={data.get('code')}: {data.get('message', 'unknown')}"
            )
        return data

    def fetch_all_shows(self, page_size: int = 50) -> List[Dict[str, Any]]:
        all_shows: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = self._get("/api/shows", params={"page": page, "pageSize": page_size})
            inner = data.get("data", {}) if isinstance(data.get("data"), dict) else {}
            shows = inner.get("list", []) if isinstance(inner, dict) else []
            if not shows:
                break
            all_shows.extend(shows)
            total = inner.get("total", 0) if isinstance(inner, dict) else 0
            if len(all_shows) >= total:
                break
            if not inner.get("hasMore", False):
                break
            page += 1
            if page > 20:
                break
        return all_shows

    def get_show_detail(self, show_id: int) -> Optional[Dict[str, Any]]:
        try:
            data = self._get(f"/api/shows/{show_id}")
            return data.get("data") if isinstance(data.get("data"), dict) else None
        except RuntimeError as e:
            logger.warning("获取演出详情 id=%s 失败: %s", show_id, e)
            shows = self.fetch_all_shows()
            for s in shows:
                if str(s.get("id")) == str(show_id):
                    return s
            return None


# ============================================================================
# 工具函数
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ticket-mcp-protected")


def _parse_show_date(show_date: Optional[str]) -> Optional[datetime]:
    if not show_date:
        return None
    try:
        s = show_date.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _filter_shows(
    shows: List[Dict[str, Any]],
    city: Optional[str] = None,
    artist: Optional[str] = None,
    keyword: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> List[Dict[str, Any]]:
    result = shows
    if city:
        city_lower = city.strip().lower()
        result = [s for s in result if city_lower in str(s.get("city", "")).lower()]
    if artist:
        artist_lower = artist.strip().lower()
        result = [s for s in result if artist_lower in str(s.get("artist", "")).lower()]
    if keyword:
        kw = keyword.strip().lower()
        result = [
            s for s in result
            if kw in str(s.get("title", "")).lower()
            or kw in str(s.get("artist", "")).lower()
            or kw in str(s.get("venue", "")).lower()
            or kw in str(s.get("city", "")).lower()
        ]
    if min_price is not None:
        result = [s for s in result if s.get("price_min") is not None and s["price_min"] >= min_price]
    if max_price is not None:
        result = [s for s in result if s.get("price_min") is not None and s["price_min"] <= max_price]
    if date_from or date_to:
        from_dt = _parse_show_date(date_from) if date_from else None
        to_dt = _parse_show_date(date_to) if date_to else None
        if date_to and to_dt and len(date_to) <= 10:
            to_dt = to_dt.replace(hour=23, minute=59, second=59)
        filtered = []
        for s in result:
            sd = _parse_show_date(s.get("show_date"))
            if sd is None:
                filtered.append(s)
                continue
            if from_dt and sd < from_dt:
                continue
            if to_dt and sd > to_dt:
                continue
            filtered.append(s)
        result = filtered
    return result


# ============================================================================
# 带数据保护的 MCP Server 构建
# ============================================================================
def build_mcp_server(api_base_url: str, host: str, port: int, sse_path: str) -> FastMCP:
    """构建 FastMCP 实例，所有工具输出均带有隐形水印和日志。"""

    mcp = FastMCP(
        name="ticket-monitor-mcp-protected",
        instructions=(
            "演出票务数据查询 MCP 服务（含数据保护）。"
            "提供搜索、推荐、比价、详情、城市列表等能力。"
            "所有响应均带有隐形数字水印和调用日志记录。"
        ),
        host=host,
        port=port,
        streamable_http_path="/mcp",
    )

    client = TicketApiClient(api_base_url)
    watermark = WatermarkManager()
    call_logger = CallLogger(log_dir="C:/ticket-monitor/mcp/logs")

    # ---------- 辅助：获取调用者上下文 ----------
    def _get_caller_ctx() -> tuple:
        """从当前 MCP 会话获取调用者 IP 和 UA。"""
        # FastMCP 的 context 中可获取请求信息
        try:
            ctx = mcp.get_context() if hasattr(mcp, 'get_context') else None
            # 降级方案：使用全局变量存储
            if ctx and hasattr(ctx, 'request'):
                headers = ctx.request.headers if hasattr(ctx.request, 'headers') else {}
                ip = headers.get("x-forwarded-for", headers.get("x-real-ip", "unknown"))
                ua = headers.get("user-agent", "unknown")
                return ip, ua
        except:
            pass
        return _caller_state.get("ip", "unknown"), _caller_state.get("ua", "unknown")

    # 用于暂存调用者上下文的线程局部变量
    _caller_state = {"ip": "unknown", "ua": "unknown"}

    def _apply_watermark(show: Dict[str, Any], fingerprint: str) -> Dict[str, Any]:
        """对单条演出数据应用水印。"""
        result = {}
        text_fields = ["title", "artist", "city", "venue", "buy_advice", "buy_advice_reason", "price_trend"]
        price_fields = ["price_min", "price_max", "predicted_price"]

        for key, val in show.items():
            if key in text_fields and isinstance(val, str) and val:
                result[key] = watermark.inject(val, fingerprint)
            elif key in price_fields:
                result[key] = watermark.inject_prices(val, fingerprint)
            else:
                result[key] = val

        # 附加不可见的溯源元数据字段
        result["_wm"] = fingerprint[:8]  # 8字符短指纹用于快速溯源
        return result

    # ---------- 中间件：拦截 SSE 连接获取客户端信息 ----------
    original_on_connect = None

    # ---------- 工具 1: search_shows ----------
    @mcp.tool()
    def search_shows(
        city: Optional[str] = None,
        artist: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        按城市、艺人或关键词搜索演出。

        Args:
            city: 城市名称（如 北京、上海、深圳）
            artist: 艺人名称（如 薛之谦、邓紫棋）
            keyword: 关键词，匹配标题、艺人、场馆、城市
            limit: 返回结果条数上限（默认 20，最大 50）

        Returns:
            匹配的演出列表，按热度从高到低排序
        """
        start_time = time.time()
        limit = max(1, min(limit, 50))
        ip, ua = _get_caller_ctx()
        fp = watermark.client_fingerprint(ip, ua)

        try:
            all_shows = client.fetch_all_shows()
        except Exception as e:
            logger.error("search_shows 拉取失败: %s", e)
            return [{"error": f"演出数据拉取失败: {e}"}]

        filtered = _filter_shows(all_shows, city=city, artist=artist, keyword=keyword)
        filtered.sort(key=lambda s: s.get("heat_index") or 0, reverse=True)
        results = [_apply_watermark(s, fp) for s in filtered[:limit]]

        duration = (time.time() - start_time) * 1000
        call_logger.log_call(ip, ua, fp, "search_shows",
                           {"city": city, "artist": artist, "keyword": keyword, "limit": limit},
                           len(json.dumps(results, ensure_ascii=False)), duration)
        return results

    # ---------- 工具 2: get_show_recommendations ----------
    @mcp.tool()
    def get_show_recommendations(
        city: Optional[str] = None,
        min_price: Optional[float] = None,
        max_price: Optional[float] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        获取演出推荐（按预算、日期、城市筛选，按热度排序）。

        Args:
            city: 目标城市
            min_price: 最低票价预算（元）
            max_price: 最高票价预算（元）
            date_from: 起始日期 YYYY-MM-DD
            date_to: 结束日期 YYYY-MM-DD
            limit: 返回条数（默认 10，最大 30）

        Returns:
            推荐演出列表
        """
        start_time = time.time()
        limit = max(1, min(limit, 30))
        ip, ua = _get_caller_ctx()
        fp = watermark.client_fingerprint(ip, ua)

        try:
            all_shows = client.fetch_all_shows()
        except Exception as e:
            logger.error("get_show_recommendations 拉取失败: %s", e)
            return [{"error": f"演出数据拉取失败: {e}"}]

        filtered = _filter_shows(all_shows, city=city, min_price=min_price,
                                max_price=max_price, date_from=date_from, date_to=date_to)
        filtered.sort(
            key=lambda s: (s.get("is_featured") or 0, s.get("is_hot") or 0, s.get("heat_index") or 0),
            reverse=True,
        )
        results = [_apply_watermark(s, fp) for s in filtered[:limit]]

        duration = (time.time() - start_time) * 1000
        call_logger.log_call(ip, ua, fp, "get_show_recommendations",
                           {"city": city, "min_price": min_price, "max_price": max_price,
                            "date_from": date_from, "date_to": date_to, "limit": limit},
                           len(json.dumps(results, ensure_ascii=False)), duration)
        return results

    # ---------- 工具 3: compare_prices ----------
    @mcp.tool()
    def compare_prices(
        show_id: Optional[int] = None,
        keyword: Optional[str] = None,
        city: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        比较同一场演出在不同平台的票价。

        Args:
            show_id: 演出 ID（推荐使用）
            keyword: 演出名称关键词（与 city 配合使用）
            city: 城市名称（与 keyword 配合使用）

        Returns:
            同场演出各平台的价格对比列表
        """
        start_time = time.time()
        ip, ua = _get_caller_ctx()
        fp = watermark.client_fingerprint(ip, ua)

        try:
            all_shows = client.fetch_all_shows()
        except Exception as e:
            logger.error("compare_prices 拉取失败: %s", e)
            return [{"error": f"演出数据拉取失败: {e}"}]

        target_shows: List[Dict[str, Any]] = []
        if show_id is not None:
            detail = client.get_show_detail(show_id)
            title = (detail or {}).get("title", "")
            city_name = (detail or {}).get("city", "")
            if title:
                target_shows = [
                    s for s in all_shows
                    if title[:8] and title[:8] in str(s.get("title", "")) and city_name == s.get("city")
                ]
            if not target_shows:
                target_shows = [detail] if detail else []
        elif keyword:
            matched = _filter_shows(all_shows, keyword=keyword, city=city)
            if not matched:
                return [{"error": "未找到匹配的演出"}]
            first = matched[0]
            title_key = str(first.get("title", ""))[:10]
            city_name = first.get("city", "")
            target_shows = [
                s for s in all_shows
                if title_key in str(s.get("title", "")) and s.get("city") == city_name
            ]
            if not target_shows:
                target_shows = matched
        else:
            return [{"error": "请提供 show_id 或 keyword 参数"}]

        platforms: Dict[str, Dict[str, Any]] = {}
        for s in target_shows:
            plat = s.get("platform") or "unknown"
            if plat not in platforms or (
                s.get("price_min") is not None
                and (platforms[plat].get("price_min") is None or s["price_min"] < platforms[plat]["price_min"])
            ):
                platforms[plat] = s

        results = [_apply_watermark(v, fp) for v in platforms.values()]
        results.sort(key=lambda s: s.get("price_min") or float("inf"))

        duration = (time.time() - start_time) * 1000
        call_logger.log_call(ip, ua, fp, "compare_prices",
                           {"show_id": show_id, "keyword": keyword, "city": city},
                           len(json.dumps(results, ensure_ascii=False)), duration)
        return results

    # ---------- 工具 4: get_show_details ----------
    @mcp.tool()
    def get_show_details(show_id: int) -> Dict[str, Any]:
        """
        获取单场演出详情，包含座位区域、价格区间、购买建议等。

        Args:
            show_id: 演出 ID（必填）

        Returns:
            演出详情对象
        """
        start_time = time.time()
        ip, ua = _get_caller_ctx()
        fp = watermark.client_fingerprint(ip, ua)

        try:
            detail = client.get_show_detail(show_id)
        except Exception as e:
            logger.error("get_show_details id=%s 失败: %s", show_id, e)
            return {"error": f"获取演出详情失败: {e}"}

        if not detail:
            return {"error": f"未找到 ID 为 {show_id} 的演出"}

        result = _apply_watermark(detail, fp)
        extra_fields = [
            "platform_url", "platform_show_id", "venue_address", "venue_capacity",
            "venue_longitude", "venue_latitude", "show_time", "show_datetime",
            "price_levels", "want_count", "supply_demand_ratio", "best_buy_date",
            "tags", "status", "sale_start_time", "sub_category",
        ]
        for f in extra_fields:
            if f in detail:
                result[f] = detail[f]

        duration = (time.time() - start_time) * 1000
        call_logger.log_call(ip, ua, fp, "get_show_details",
                           {"show_id": show_id},
                           len(json.dumps(result, ensure_ascii=False)), duration)
        return result

    # ---------- 工具 5: get_cities ----------
    @mcp.tool()
    def get_cities() -> List[str]:
        """获取当前有演出的全部城市列表。"""
        start_time = time.time()
        ip, ua = _get_caller_ctx()
        fp = watermark.client_fingerprint(ip, ua)

        try:
            all_shows = client.fetch_all_shows()
        except Exception as e:
            logger.error("get_cities 拉取失败: %s", e)
            return [f"error: {e}"]

        cities = sorted({s.get("city") for s in all_shows if s.get("city")})
        # 对城市名也加水印（第一个城市）
        if cities:
            cities[0] = watermark.inject(cities[0], fp)

        duration = (time.time() - start_time) * 1000
        call_logger.log_call(ip, ua, fp, "get_cities", {},
                           len(json.dumps(cities, ensure_ascii=False)), duration)
        return cities

    # ---------- 工具 6: get_call_stats (运维/取证用) ----------
    @mcp.tool()
    def get_call_stats() -> Dict[str, Any]:
        """
        获取 MCP 服务调用统计（仅管理员使用）。

        Returns:
            调用次数、独立客户端数量等统计信息
        """
        return call_logger.get_stats()

    return mcp


# ============================================================================
# 水印验证工具（独立使用，用于维权取证）
# ============================================================================
def verify_data_source(text: str) -> Optional[Dict[str, Any]]:
    """
    从可疑数据中提取水印，判断数据来源。
    用法: python ticket_mcp_server_protected.py verify "可疑的文本数据"
    """
    wm = WatermarkManager()
    fp = wm.verify(text)
    if fp:
        return {
            "watermark_found": True,
            "fingerprint": fp,
            "note": "指纹匹配成功，可通过日志反查调用者 IP 和时间",
        }
    return {"watermark_found": False, "note": "未检测到水印"}


# ============================================================================
# 启动入口
# ============================================================================
def main() -> None:
    result_mode = sys.argv[1] if len(sys.argv) > 1 else "display_only"
    api_base_url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3000"
    host = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 8000
    sse_path = sys.argv[5] if len(sys.argv) > 5 else "/sse"

    # 支持 verify 子命令
    if result_mode == "verify" and len(sys.argv) > 6:
        result = verify_data_source(sys.argv[6])
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    logger.info("=" * 60)
    logger.info("演出票务 MCP Server (带数据保护)")
    logger.info("=" * 60)
    logger.info("  API 地址  : %s", api_base_url)
    logger.info("  监听地址  : %s:%d", host, port)
    logger.info("  SSE 路径  : %s", sse_path)
    logger.info("  水印系统  : 已启用 (零宽字符 + 价格微偏移)")
    logger.info("  调用日志  : C:/ticket-monitor/mcp/logs/mcp_access.log")
    logger.info("=" * 60)

    mcp = build_mcp_server(api_base_url, host, port, sse_path)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
