# SafeToolHunter

SafeToolHunter 是一个自动化安全工具扫描程序，旨在通过FOFA搜索引擎搜索特定类型的安全工具和漏洞平台，然后批量检测这些工具的默认凭证漏洞。

## 功能特点

- 自动搜索8种常见安全工具：DVWA、Nessus、ARL、Supershell、Vshell、Vulfocus、PentAGI、XuanMu
- 多线程并发检测，提高扫描效率
- 自动数据清理，验证主机存活状态
- 结果自动入库MySQL数据库
- 支持定时任务自动化执行

## 依赖要求

- Python 3.6+
- MySQL数据库

### Python依赖

```bash
pip install -r requirements.txt
```

依赖包包括：
- beautifulsoup4
- pymysql
- requests
- tqdm

## 配置

仓库只提供模板，真实配置需自行创建（`config/dbconfig.json` 与 `config/fofaconfig.json` 已被 `.gitignore` 排除）：

```bash
cp config/dbconfig.example.json    config/dbconfig.json
cp config/fofaconfig.example.json  config/fofaconfig.json
```

详见 [`config/README.md`](config/README.md)。

### 数据库配置

编辑 `config/dbconfig.json` 文件配置MySQL数据库连接：

```json
{
  "host": "your_database_host",
  "port": 3306,
  "user": "your_database_user",
  "password": "your_database_password",
  "database": "your_database_name",
  "charset": "utf8mb4"
}
```

### FOFA配置

编辑 `config/fofaconfig.json` 文件配置FOFA API：

```json
{
  "base_url": "https://fofa.info/api/v1/search/all",
  "key": "your_fofa_api_key"
}
```

## 使用方法

### 手动运行

```bash
python safeToolHunter.py
```

程序将按以下顺序执行：
1. 数据清理（检查并清理数据库中的无效主机）
2. 漏洞检测（对各类安全工具进行默认凭证检测）

### 定时任务运行

程序默认配置了crontab定时任务，每天零点执行，到凌晨4点停止：

```bash
# 每天零点自动执行程序抓肉鸡，最多运行到4点就停止程序
0 0 * * * sh /path/to/start.sh
0 4 * * * ps aux | grep safeToolHunter.py | grep -v grep | awk '{print $2}' | xargs -r kill -9
```

### 启动脚本

修改 `start.sh` 文件，将其指向正确的项目路径：

```bash
#!/bin/bash

# 设置指定的工作目录路径
TARGET_DIR="/your/actual/path/to/safeToolHunter"

# 切换到指定路径
cd "$TARGET_DIR" || { echo "无法切换到目录 $TARGET_DIR"; exit 1; }

# 执行 Python 脚本
python safeToolHunter.py  > log.txt 2>&1
```

## 程序结构

```
safeToolHunter/
├── safeToolHunter.py          # 主程序入口
├── requirements.txt           # Python依赖列表
├── run.sh                     # 定时任务入口（按天切分日志、保留 30 份）
├── crontab.txt                # 定时任务配置
├── .gitignore                 # 排除凭据与运行产物
├── config/                    # 配置文件目录
│   ├── README.md              # 配置说明
│   ├── dbconfig.example.json  # 数据库配置模板（复制为 dbconfig.json）
│   └── fofaconfig.example.json  # FOFA API 配置模板（复制为 fofaconfig.json）
├── sql/
│   └── schema.sql             # 手工建表脚本（程序启动时也会自动建表）
├── result/                    # 搜索结果存储目录（运行时生成，不入库）
├── tools/                     # 工具模块目录
│   ├── db.py                  # 数据库操作模块
│   ├── data_clean.py          # 数据清理模块
│   ├── fofa_search.py         # FOFA搜索模块
│   ├── vuln_checker.py        # 漏洞检测模块（含 MAX_CHECK_PER_TYPE 探测上限）
│   └── vuln_check/            # 具体漏洞检测器目录
│       ├── arl_checker.py
│       ├── dvwa_checker.py
│       ├── nessus_checker.py
│       ├── supershell_checker.py
│       ├── vshell_checker.py
│       ├── vulnfocus_checker.py
│       ├── pentagi_checker.py
│       └── xuanmu_checker.py
└── README.md                  # 项目说明
```

## 支持的工具类型

| 工具类型 | 检测内容 |
|----------|----------|
| dvwa | DVWA漏洞测试平台默认账密 (admin/password) |
| nessus | Tenable Nessus漏洞扫描器 |
| arl | 资产灯塔系统默认账密 (admin/arlpass) |
| supershell | Supershell远控平台 |
| vshell | Vshell远程控制工具 |
| vulnfocus | Vulfocus漏洞靶场默认账密 (admin/admin) |
| pentagi | PentAGI自动化渗透平台默认账密 (admin@pentagi.com/admin) |
| xuanmu | XuanMu红队代理默认账密 (admin@admin.com/admin123) |

## 结果存储

- 搜索结果保存在 `result/` 目录的JSON文件中，同名 `*_meta.json` 记录查询语句与搜索时间
- 资产（每次 FOFA 搜到的所有 host）写入 `Assets` 表，带首次/最新发现时间
- 弱口令命中写入 `DefaultPass` 表
- 每次运行在 `ScanRuns` 表留一条批次记录，并在控制台输出耗时统计

## 数据库表结构

程序启动时会自动建表/自动补列（`tools/db.py: ensure_schema`），也提供手工版本 `sql/schema.sql`。

### Assets（资产发现时间，核心改进）

| 字段 | 说明 |
|------|------|
| `host` | 主机（含端口），与 `type_val` 组成唯一键 |
| `type_val` | 工具类型：dvwa/nessus/arl/... |
| `first_seen` | **首次发现时间**（只写一次，之后不再变） |
| `last_seen` | **最新发现时间**（每次 FOFA 再搜到就刷新） |
| `seen_count` | 累计被搜到次数 |
| `last_check_at` / `last_check_status` | 最近一次检测时间与结果（cred_ok/cred_fail/dead/error） |
| `is_alive` | 主机当前是否可用（清洗时置 0，不删记录） |

### DefaultPass（弱口令命中）

原有 `host(唯一) / username / password / type_val` 之外新增：
`first_seen`（首次命中）、`last_seen`（最近一次确认仍可用）、`last_check_at`、`seen_count`、`is_valid`。

### ScanRuns（扫描批次）

`run_type / source(fofa|json) / started_at / finished_at / hosts_seen / findings`。

### 查“最新发现”的三种方式

```sql
-- 1) 视图：按最新发现时间倒序
SELECT * FROM v_assets_latest LIMIT 20;

-- 2) 某类型最近 7 天新出现的资产
SELECT host, first_seen FROM Assets
WHERE type_val='arl' AND first_seen > NOW() - INTERVAL 7 DAY
ORDER BY first_seen DESC;
```

```bash
# 3) 命令行
python safeToolHunter.py --latest 20
python safeToolHunter.py --latest 50 --type arl
```

## 命令行参数

```bash
python safeToolHunter.py                     # 默认：清洗 + FOFA 搜索 + 默认口令检测
python safeToolHunter.py --init-db           # 只建表/迁移
python safeToolHunter.py --latest 20         # 看最新发现的资产
python safeToolHunter.py --stats             # 按类型汇总：资产数/今日新增/最新发现时间
python safeToolHunter.py --skip-clean        # 跳过数据清洗
python safeToolHunter.py --types dvwa,arl    # 只跑指定类型
python safeToolHunter.py --from-json --record-only   # 离线：只登记历史结果里的资产，不联网不检测
python safeToolHunter.py --clean-mode hard   # 清洗时直接删除（默认为标记失效）
```

## 探测数量上限

`tools/vuln_checker.py` 中的 `MAX_CHECK_PER_TYPE` 可限制某类型单次最多探测的目标数：

```python
MAX_CHECK_PER_TYPE = {
    "dvwa": 100,   # dvwa 单次最多探测 100 条；其余类型缺省不限制
}
```

要点：

- **资产发现不受影响**：FOFA 搜到的目标仍全量写入 `Assets` 表，`first_seen` / `last_seen` 正常维护。
- **只限制主动探测**：从该类型的目标中**随机抽取**至多 N 条做默认口令检测，因此长期运行能逐步覆盖全量资产。
- 某类型不需要限制时，从字典中删掉对应键即可（或设为 `None`）。

典型用途：`dvwa` 资产量往往上千，每条要发两次 HTTP 请求（取 CSRF + 登录），耗时远高于其他类型，适合压低上限。

## 部署（Ubuntu + MariaDB）

```bash
apt-get install -y mariadb-server python3-venv
mysql -e "CREATE DATABASE readteam DEFAULT CHARSET utf8mb4;"
# 写 config/dbconfig.json 指向本地库后：
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python safeToolHunter.py --init-db
```

定时任务见 `crontab.txt`，入口脚本 `run.sh`（自动按天切分日志、保留 30 份）。

## 注意事项

1. 请确保拥有合法权限进行安全检测
2. 使用FOFA API需要有效的API密钥
3. 请妥善管理配置文件中的敏感信息
4. 运行时请确保有充足的网络和计算资源
5. 在生产环境中使用时请考虑对目标系统的性能影响

## 许可证

此项目仅供教育和授权渗透测试使用。使用者需确保其使用行为符合当地法律法规。

## 贡献

欢迎提交Issue和Pull Request来改进此项目。