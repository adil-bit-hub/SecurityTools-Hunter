import base64
import json
from datetime import datetime
from pathlib import Path

import requests

# 项目根目录，避免依赖启动时的工作目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULT_DIR = PROJECT_ROOT / "result"
CONFIG_PATH = PROJECT_ROOT / "config" / "fofaconfig.json"

# 支持的工具类型 -> FOFA 查询语句
QUERIES = {
    "dvwa": 'app="DVWA"',
    "nessus": 'app="tenable-Nessus"',
    "arl": 'app="资产灯塔系统"',
    "supershell": 'app="Supershell-远控平台"',
    "vshell": 'app="Vshell-RAT"',
    "vulnfocus": 'title="Vulfocus"',
    "pentagi": '(title="PentAGI" || body="PentAGI") && port="8443"',
    "xuanmu": 'title="XuanMu RedTeam Agent"',
}


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# Fofa 搜索函数
def fofa_search(value, size=10000):
    config = load_config()
    BASE_URL = config.get("base_url")
    KEY = config.get("key")

    if not value or not isinstance(value, str):
        return {"error": "Query string must be a non-empty string"}
    try:
        query = base64.b64encode(value.encode(encoding="utf-8")).decode("utf-8")
        payload = {
            "key": KEY,
            "qbase64": query,
            "size": str(size),
            "fields": "host",
        }
        resp = requests.get(BASE_URL, params=payload, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# 处理URL列表：去除 http(s):// 前缀，汇总后去重
# Fofa API 指定 fields='host' 时，results 为 [[host1], [host2], ...] 嵌套列表
def process_url_list(url_list):
    processed = []
    for item in url_list:
        if isinstance(item, list):
            item = item[0] if item else ""
        if not isinstance(item, str) or not item:
            continue
        if item.startswith("https://"):
            cleaned = item[len("https://"):]
        elif item.startswith("http://"):
            cleaned = item[len("http://"):]
        else:
            cleaned = item
        processed.append(cleaned)

    return list(set(processed))


def load_from_json(type_name):
    """离线模式：直接读 result/<type>_fofa.json，不消耗 FOFA 额度"""
    path = RESULT_DIR / f"{type_name}_fofa.json"
    if not path.exists():
        print(f"[!] 离线数据不存在: {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[*] 从本地文件读取 {type_name}: {len(data)} 条")
    return data


# 主函数：搜索 + 去重 + 落盘 + 写入 Assets（记录发现时间）
def main(type_name, persist=True, db_handler=None, seen_at=None):
    if type_name not in QUERIES:
        print("不支持该类型的搜索，请检查输入参数是否正确！\n"
              f"当前支持 {', '.join(QUERIES)} 共 {len(QUERIES)} 种资产类型检索")
        return []

    print("[*] 正在使用 Fofa 进行搜索...")
    hosts = fofa_search(QUERIES[type_name])

    if isinstance(hosts, dict) and (hosts.get("error") or hosts.get("errmsg")):
        err_msg = hosts.get("errmsg", hosts.get("error", "未知错误"))
        print(f"[!] Fofa API 返回错误: {err_msg}")
        return []

    if not isinstance(hosts, dict) or "results" not in hosts:
        print("[!] Fofa API 返回格式异常，无法解析结果")
        return []

    print("搜索完成，结果去重中...")
    unique_result = process_url_list(hosts["results"])
    seen_at = seen_at or datetime.now()
    print(f"去重完成，结果有{len(unique_result)}条数据需处理...")

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULT_DIR / f"{type_name}_fofa.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(unique_result, f, ensure_ascii=False, indent=4)
    # 附带一份元信息，方便追溯“这批数据是什么时候搜的”
    meta = {
        "type": type_name,
        "query": QUERIES[type_name],
        "searched_at": seen_at.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(unique_result),
    }
    with open(RESULT_DIR / f"{type_name}_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"结果已保存至 {out_file}（{meta['searched_at']}）")

    # 资产入库：新 host 记 first_seen，老 host 只刷新 last_seen
    if persist:
        try:
            if db_handler is None:
                from tools.db import DatabaseHandler
                db_handler = DatabaseHandler()
            n = db_handler.upsert_assets(type_name, unique_result, seen_at=seen_at)
            print(f"[db] 资产发现时间已入库：{n} 条（type={type_name}）")
        except Exception as e:
            print(f"[!] 资产入库失败（不影响本次检测）: {e}")

    return unique_result
