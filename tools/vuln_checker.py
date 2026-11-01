from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime
import random
import threading

from tqdm import tqdm

from tools.vuln_check.arl_checker import arl_checker
from tools.vuln_check.dvwa_checker import dvwa_checker
from tools.vuln_check.vulnfocus_checker import vulnfocus_checker
from tools.vuln_check.vshell_checker import vshell_checker
from tools.vuln_check.supershell_checker import supershell_checker
from tools.vuln_check.nessus_checker import nessus_checker
from tools.vuln_check.pentagi_checker import pentagi_checker
from tools.vuln_check.xuanmu_checker import xuanmu_checker
from tools.db import DatabaseHandler
from tools import fofa_search as fofa_module

# 配置与初始化
checker_map = {
    "xuanmu": xuanmu_checker,
    "pentagi": pentagi_checker,
    "vulnfocus": vulnfocus_checker,
    "nessus": nessus_checker,
    "arl": arl_checker,
    "supershell": supershell_checker,
    "vshell": vshell_checker,
    "dvwa": dvwa_checker,
}
# 每个类型单次最多探测的目标数（None/缺省 = 不限制）；资产发现仍按全量入库
MAX_CHECK_PER_TYPE = {
    "dvwa": 100,
}
MAX_WORKERS = 50  # 线程池最大并发数
TASK_TIMEOUT = 30  # 单个任务超时时间（秒）
db_handler = DatabaseHandler()  # 数据库连接（全局单例）
db_lock = threading.Lock()  # 数据库操作锁


def check_single_host(task_args):
    """单个主机检测任务（供线程池调用）"""
    task_type, host = task_args
    checker = checker_map.get(task_type)

    if not checker:
        return (False, f"不支持的类型: {task_type}", host, True)

    try:
        result_data = checker(host)
        if result_data:
            with db_lock:
                db_result = db_handler.upsert_host_data(
                    host=result_data.get("host"),
                    username=result_data.get("username"),
                    password=result_data.get("password"),
                    type_val=result_data.get("type") or task_type,
                    seen_at=datetime.now(),
                )
                db_handler.mark_asset_checked(
                    result_data.get("host"), task_type, "cred_ok"
                )
            return (True, f"检测成功: {db_result}", host, False)

        with db_lock:
            db_handler.mark_asset_checked(host, task_type, "cred_fail")
        return (True, "", host, True)

    except Exception:
        with db_lock:
            try:
                db_handler.mark_asset_checked(host, task_type, "error")
            except Exception:
                pass
        return (True, "", host, True)


def process_type(task_type, hosts=None, record_only=False):
    """处理单个类型的所有主机检测，返回统计"""
    print(f"\n[*] 开始处理类型: {task_type}")

    if hosts is None:
        hosts = fofa_module.main(task_type, persist=True, db_handler=db_handler)

    total = len(hosts)
    stats = {"type": task_type, "total": total, "found": 0, "failed": 0}
    print(f"[*] {task_type} 共获取到 {total} 个目标")

    if total == 0:
        print(f"[*] {task_type} 无目标，跳过处理\n")
        return stats

    if record_only:
        # 只记录资产发现时间，不做任何主动检测（不碰目标）
        try:
            db_handler.upsert_assets(task_type, hosts, seen_at=datetime.now())
        except Exception as e:
            print(f"[!] 资产入库失败: {e}")
        print(f"[*] {task_type} 已记录 {total} 条资产（仅登记，未检测）\n")
        return stats

    # 探测数量上限：资产仍全量入库，只限制主动探测的目标条数
    check_hosts = hosts
    max_check = MAX_CHECK_PER_TYPE.get(task_type)
    if max_check is not None and total > max_check:
        check_hosts = random.sample(hosts, max_check)
        print(f"[*] {task_type} 探测上限 {max_check} 条"
              f"（从 {total} 条中随机抽取，资产仍全量登记）")

    stats["checked"] = len(check_hosts)
    tasks = [(task_type, host) for host in check_hosts]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_host = {executor.submit(check_single_host, arg): arg[1] for arg in tasks}

        for future in tqdm(
            as_completed(future_to_host), total=len(check_hosts), desc=f"[{task_type}] 检测进度"
        ):
            host = future_to_host[future]
            try:
                success, msg, _, is_no_data = future.result(timeout=TASK_TIMEOUT)
                if is_no_data:
                    stats["failed"] += 1
                    continue
                stats["found"] += 1
                status = "成功" if success else "失败"
                print(f"[{status}] {host}: {msg}")
            except TimeoutError:
                stats["failed"] += 1
                print(f"[超时] {host}: 任务执行超过{TASK_TIMEOUT}秒，已终止")
            except Exception as e:
                stats["failed"] += 1
                print(f"[线程错误] {host}: {str(e)}")

    print(f"[*] {task_type} 处理完成（命中 {stats['found']} / 探测 {stats.get('checked', total)} / 资产总数 {total}）\n")
    return stats


def main(types=None, hosts_map=None, record_only=False):
    """types: 指定要跑的类型；hosts_map: {type: [host,...]} 用于离线复跑"""
    print("[*] 开始执行漏洞检查任务...")
    selected = types or list(checker_map.keys())
    all_stats = []

    run_id = None
    try:
        run_id = db_handler.start_run(",".join(selected), "json" if hosts_map else "fofa")
    except Exception as e:
        print(f"[!] 扫描批次记录失败: {e}")

    for task_type in selected:
        if task_type not in checker_map:
            print(f"[!] 跳过未知类型: {task_type}")
            continue
        hosts = (hosts_map or {}).get(task_type)
        all_stats.append(process_type(task_type, hosts=hosts, record_only=record_only))

    if run_id:
        try:
            db_handler.finish_run(
                run_id,
                hosts_seen=sum(s["total"] for s in all_stats),
                findings=sum(s["found"] for s in all_stats),
                note="record_only" if record_only else None,
            )
        except Exception as e:
            print(f"[!] 扫描批次收尾失败: {e}")

    print("[+] 所有任务处理完毕")
    return all_stats
