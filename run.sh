#!/bin/bash
# SafeToolHunter 定时任务入口（cron 调用）
#   ./run.sh                 全量：清洗 + FOFA 搜索 + 默认口令检测
#   ./run.sh --record-only   只登记资产发现时间，不主动检测
#   ./run.sh --types dvwa,arl --from-json   离线复跑
set -u
APP="/opt/safeToolHunter"
cd "$APP" || { echo "无法切换到 $APP"; exit 1; }

mkdir -p logs
LOG="logs/run-$(date +%Y%m%d-%H%M%S).log"
.venv/bin/python safeToolHunter.py "$@" >>"$LOG" 2>&1
rc=$?
echo "[$(date '+%F %T')] exit=$rc log=$LOG"
# 只保留最近 30 份日志
ls -1t logs/run-*.log 2>/dev/null | tail -n +31 | xargs -r rm -f
exit $rc
