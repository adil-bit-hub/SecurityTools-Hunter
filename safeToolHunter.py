import argparse
import os
import sys
import time
from pathlib import Path

import tools.vuln_checker as vuln_checker
import tools.data_clean as data_clean
from tools.db import DatabaseHandler
from tools import fofa_search

banner = r'''
 ______     __  __     ______     ______     __  __
/\  ___\   /\ \_\ \   /\  ___\   /\  ___\   /\ \/ /
\ \ \____  \ \  __ \  \ \  __\   \ \ \____  \ \  _"-
 \ \_____\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\ \_\
  \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/

  Code by Adil
'''


def print_latest(limit=20, type_val=None):
    """打印按“最新发现时间”倒序的资产列表"""
    handler = DatabaseHandler()
    rows = handler.fetch_latest_assets(limit=limit, type_val=type_val)
    if not rows:
        print("[!] Assets 表暂无数据")
        return
    header = (f"{'host':45} {'type':10} {'首次发现':19} {'最新发现':19} "
              f"{'次数':>4} {'状态':10} {'存活':>4}")
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['host'][:45]:45} {r['type_val'][:10]:10} "
            f"{str(r['first_seen'])[:19]:19} {str(r['last_seen'])[:19]:19} "
            f"{r['seen_count']:>4} {str(r['last_check_status'] or '-'):10} "
            f"{'是' if r['is_alive'] else '否':>4}"
        )


def print_stats():
    """按类型汇总资产规模与最新发现时间"""
    handler = DatabaseHandler()
    rows = handler.stats_by_type()
    if not rows:
        print("[!] Assets 表暂无数据")
        return
    header = (f"{'type':12} {'资产数':>7} {'今日新增':>8} {'今日再现':>8} "
              f"{'最早发现':19} {'最新发现':19}")
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['type_val'][:12]:12} {r['assets']:>7} {int(r['new_today'] or 0):>8} "
            f"{int(r['seen_today'] or 0):>8} {str(r['earliest_seen'])[:19]:19} "
            f"{str(r['latest_seen'])[:19]:19}"
        )
    print("-" * len(header))
    print(f"{'合计':12} {sum(r['assets'] for r in rows):>7} "
          f"{sum(int(r['new_today'] or 0) for r in rows):>8} "
          f"{sum(int(r['seen_today'] or 0) for r in rows):>8}")


def main():
    parser = argparse.ArgumentParser(description="SafeToolHunter 安全工具资产发现与默认口令检测")
    parser.add_argument("--init-db", action="store_true", help="建表/迁移后退出")
    parser.add_argument("--latest", type=int, metavar="N", help="列出最近发现的 N 条资产后退出")
    parser.add_argument("--stats", action="store_true", help="按类型汇总资产数与最新发现时间后退出")
    parser.add_argument("--type", dest="type_val", help="配合 --latest，只看某个类型")
    parser.add_argument("--skip-clean", action="store_true", help="跳过数据清洗")
    parser.add_argument("--clean-mode", choices=["soft", "hard"], default="soft",
                        help="清洗方式：soft=标记失效（默认，保留历史），hard=直接删除")
    parser.add_argument("--types", help="只跑指定类型，逗号分隔，如 arl,dvwa")
    parser.add_argument("--from-json", action="store_true",
                        help="离线模式：用 result/<type>_fofa.json，不调用 FOFA API")
    parser.add_argument("--record-only", action="store_true",
                        help="只登记资产发现时间，不做任何主动检测")
    parser.add_argument("--limit", type=int, default=100000, help="清洗时最多读取的记录数")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    os.chdir(project_root)

    if args.init_db:
        print(banner)
        DatabaseHandler().ensure_schema()
        print("[+] 表结构就绪")
        return

    if args.latest or args.stats:
        DatabaseHandler().ensure_schema(verbose=False)
        if args.stats:
            print_stats()
        if args.latest:
            print()
            print_latest(args.latest, args.type_val)
        return

    print(banner)
    print(f"当前工作目录已设置为: {project_root}")
    for folder in ("result", "config"):
        (project_root / folder).mkdir(exist_ok=True)

    handler = DatabaseHandler()
    handler.ensure_schema(verbose=False)

    types = [t.strip() for t in args.types.split(",")] if args.types else None

    if not args.skip_clean:
        clean_start = time.time()
        data_clean.main(mode=args.clean_mode, limit=args.limit)
        print(f"数据清理完成，耗时: {time.time() - clean_start:.2f}秒")
    else:
        print("[*] 已跳过数据清洗")

    check_start = time.time()
    if args.from_json:
        hosts_map = {}
        for t in (types or list(fofa_search.QUERIES)):
            hosts = fofa_search.load_from_json(t)
            if hosts:
                hosts_map[t] = hosts
        vuln_checker.main(types=types, hosts_map=hosts_map, record_only=args.record_only)
    else:
        vuln_checker.main(types=types, record_only=args.record_only)

    print(f"漏洞检查完成,耗时: {time.time() - check_start:.2f}秒")
    print("[*] 查看最新资产: python safeToolHunter.py --latest 20")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已手动中断")
        sys.exit(130)
