import concurrent.futures
import json
import time

import requests

from tools.db import DatabaseHandler

# 禁用requests的安全警告
requests.packages.urllib3.disable_warnings()

# 数据库连接（全局单例，仅用于读取数据）
db_handler = DatabaseHandler()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
}
TIMEOUT = 10  # 单个请求超时（秒）
MAX_WORKERS = 50


def is_host_dead(host):
    """HTTP/HTTPS 都不通时认为主机已失效。返回 True 表示失效。"""
    try:
        req_http = requests.get(f"http://{host}", timeout=TIMEOUT, headers=HEADERS)
        if req_http.status_code < 400:
            return False
    except Exception:
        pass

    try:
        req_https = requests.get(
            f"https://{host}", verify=False, timeout=TIMEOUT, headers=HEADERS
        )
        if req_https.status_code < 400:
            return False
    except Exception:
        pass

    return True


def clean_data(entry, mode="soft"):
    """清理单条记录；mode=soft 只标记失效，保留历史发现时间"""
    host = entry.get("host")
    type_val = entry.get("type_val") or entry.get("type") or ""
    handler = DatabaseHandler()  # 每个线程独立连接
    try:
        if not is_host_dead(host):
            return False
        if mode == "hard":
            handler.delete_by_host(host)
        else:
            handler.invalidate_by_host(host)
            handler.mark_asset_dead(host, type_val)
        return True
    finally:
        handler.close()


def clean_data_in_parallel(all_data, max_workers=MAX_WORKERS, mode="soft"):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda entry: clean_data(entry, mode), all_data)
        return sum(1 for result in results if result)


def main(mode="soft", limit=100000):
    print("[*] 开始执行数据清洗任务...")
    all_data_json = db_handler.fetch_data(limit=limit)
    all_data = json.loads(all_data_json)
    if isinstance(all_data, dict) and all_data.get("error"):
        print(f"[!] 读取数据失败，跳过清洗: {all_data['error']}")
        return 0

    total = len(all_data)
    print(f"[*] 共获取到 {total} 条数据，开始逐条检测...")

    start_time = time.time()
    cleaned_count = clean_data_in_parallel(all_data, mode=mode)
    end_time = time.time()

    action = "删除" if mode == "hard" else "标记失效"
    print(f"[*] 数据清洗完成，共{action} {cleaned_count} 条无效记录。")
    print(f"[*] 清理任务完成，耗时 {end_time - start_time:.2f} 秒。")
    return cleaned_count
