import json
import os
from datetime import datetime
from pathlib import Path

import pymysql
from pymysql import OperationalError, IntegrityError

# 项目根目录（tools/ 的上一级），避免依赖启动时的工作目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "dbconfig.json"

# 资产表：每一条 (host, type) 记录一份“首次发现 / 最近一次发现”时间
ASSETS_DDL = """
CREATE TABLE IF NOT EXISTS Assets (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host          VARCHAR(255)    NOT NULL,
  type_val      VARCHAR(64)     NOT NULL,
  first_seen    DATETIME        NOT NULL COMMENT '首次发现时间',
  last_seen     DATETIME        NOT NULL COMMENT '最近一次被 FOFA 发现的时间',
  seen_count    INT UNSIGNED    NOT NULL DEFAULT 1 COMMENT '累计被搜索到次数',
  last_check_at DATETIME        NULL COMMENT '最近一次指纹/口令检测时间',
  last_check_status VARCHAR(32) NULL COMMENT 'cred_ok / cred_fail / dead / error',
  is_alive      TINYINT(1)      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uk_host_type (host, type_val),
  KEY idx_last_seen (last_seen),
  KEY idx_type_last_seen (type_val, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='FOFA 发现资产及其最新发现时间'
"""

DEFAULTPASS_DDL = """
CREATE TABLE IF NOT EXISTS DefaultPass (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host          VARCHAR(255)    NOT NULL,
  username      VARCHAR(255)    NULL,
  password      VARCHAR(255)    NULL,
  type_val      VARCHAR(64)     NULL,
  first_seen    DATETIME        NULL COMMENT '首次命中弱口令时间',
  last_seen     DATETIME        NULL COMMENT '最近一次确认弱口令仍可用的时间',
  last_check_at DATETIME        NULL,
  seen_count    INT UNSIGNED    NOT NULL DEFAULT 1,
  is_valid      TINYINT(1)      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uk_host (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='弱口令命中结果'
"""

SCANRUNS_DDL = """
CREATE TABLE IF NOT EXISTS ScanRuns (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_type    VARCHAR(64)     NOT NULL COMMENT '类型或 all',
  source      VARCHAR(16)     NOT NULL COMMENT 'fofa / json / manual',
  started_at  DATETIME        NOT NULL,
  finished_at DATETIME        NULL,
  hosts_seen  INT UNSIGNED    NOT NULL DEFAULT 0,
  findings    INT UNSIGNED    NOT NULL DEFAULT 0,
  note        VARCHAR(255)    NULL,
  PRIMARY KEY (id),
  KEY idx_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='每次扫描批次'
"""

# 老库可能存在的表缺少这些列，启动时自动补齐
MIGRATIONS = {
    "DefaultPass": [
        ("first_seen", "DATETIME NULL"),
        ("last_seen", "DATETIME NULL"),
        ("last_check_at", "DATETIME NULL"),
        ("seen_count", "INT UNSIGNED NOT NULL DEFAULT 1"),
        ("is_valid", "TINYINT(1) NOT NULL DEFAULT 1"),
    ],
    "Assets": [
        ("last_check_at", "DATETIME NULL"),
        ("last_check_status", "VARCHAR(32) NULL"),
        ("is_alive", "TINYINT(1) NOT NULL DEFAULT 1"),
        ("seen_count", "INT UNSIGNED NOT NULL DEFAULT 1"),
    ],
}


class DatabaseHandler:
    """数据库操作工具类，封装查询和新增/更新功能"""

    def __init__(self, config_path=None):
        """初始化数据库配置（默认读取项目根目录 config/dbconfig.json）"""
        cfg_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        with open(cfg_path, "r", encoding="utf-8") as f:
            self.db_config = json.load(f)
        # 补齐常用连接参数；其中 ssl 相关键保持原样
        self.db_config.setdefault("charset", "utf8mb4")
        self.db_config.setdefault("connect_timeout", 10)
        self.db_config.setdefault("autocommit", True)
        self.conn = None

    def _get_connection(self):
        """获取数据库连接（内部使用）"""
        try:
            return pymysql.connect(**self.db_config)
        except OperationalError as e:
            raise Exception(f"数据库连接失败: {str(e)}")

    # ------------------------------------------------------------------
    # 表结构：建表 + 自动迁移
    # ------------------------------------------------------------------
    def ensure_schema(self, verbose=True):
        """建表（幂等），并给老表补齐新增列。返回新建/补齐的动作列表。"""
        actions = []
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                for ddl in (ASSETS_DDL, DEFAULTPASS_DDL, SCANRUNS_DDL):
                    cursor.execute(ddl)
                    actions.append(f"DDL ok: {ddl.split()[5]}")
                conn.commit()

            for table, columns in MIGRATIONS.items():
                existing = self._columns(conn, table)
                for col, definition in columns:
                    if col not in existing:
                        with conn.cursor() as cursor:
                            cursor.execute(
                                f"ALTER TABLE `{table}` ADD COLUMN `{col}` {definition}"
                            )
                        conn.commit()
                        actions.append(f"ALTER {table} ADD {col}")

            # 视图：按“最新发现时间”倒序看资产
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE OR REPLACE VIEW v_assets_latest AS
                    SELECT host, type_val, first_seen, last_seen,
                           TIMESTAMPDIFF(HOUR, last_seen, NOW()) AS age_hours,
                           seen_count, last_check_status, is_alive
                    FROM Assets
                    ORDER BY last_seen DESC
                    """
                )
                conn.commit()
                actions.append("VIEW ok: v_assets_latest")

        if verbose:
            for a in actions:
                print(f"[schema] {a}")
        return actions

    @staticmethod
    def _columns(conn, table):
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
                (table,),
            )
            return {row[0] for row in cursor.fetchall()}

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def fetch_rows(self, limit=10, table="DefaultPass", order_by="host"):
        """返回字典列表（内部使用；limit=None 表示不限制）"""
        sql = f"SELECT * FROM `{table}` ORDER BY `{order_by}`"
        params = ()
        if limit is not None:
            sql += " LIMIT %s"
            params = (int(limit),)
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, params) if params else cursor.execute(sql)
                columns = [d[0] for d in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def fetch_data(self, limit=10):
        """兼容旧接口：返回 JSON 字符串"""
        try:
            rows = self.fetch_rows(limit=limit)
            print(f"查询到 {len(rows)} 条记录")
            return json.dumps(rows, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            error_msg = f"查询失败: {str(e)}"
            print(error_msg)
            return json.dumps({"error": error_msg}, ensure_ascii=False)

    def stats_by_type(self):
        """按类型汇总：资产数、今日新增、今日被再次发现数、最早/最新发现时间"""
        sql = """
            SELECT type_val,
                   COUNT(*)                                   AS assets,
                   SUM(first_seen >= CURDATE())               AS new_today,
                   SUM(last_seen  >= CURDATE())               AS seen_today,
                   MIN(first_seen)                            AS earliest_seen,
                   MAX(last_seen)                             AS latest_seen
              FROM Assets
             GROUP BY type_val
             ORDER BY assets DESC
        """
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql)
                columns = [d[0] for d in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def fetch_latest_assets(self, limit=20, type_val=None):
        """按最近发现时间倒序列出资产"""
        sql = (
            "SELECT host, type_val, first_seen, last_seen, seen_count, "
            "       last_check_status, is_alive "
            "FROM Assets"
        )
        params = []
        if type_val:
            sql += " WHERE type_val = %s"
            params.append(type_val)
        sql += " ORDER BY last_seen DESC LIMIT %s"
        params.append(int(limit))
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, params)
                columns = [d[0] for d in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def upsert_assets(self, type_val, hosts, seen_at=None):
        """把一批 FOFA 发现的 host 写入 Assets：
        新 host 记 first_seen=last_seen，老 host 只刷新 last_seen 并把 seen_count+1。
        返回写入条数。
        """
        if not hosts:
            return 0
        now = seen_at or datetime.now()
        rows = [(h, type_val, now, now) for h in hosts]
        sql = """
            INSERT INTO Assets (host, type_val, first_seen, last_seen)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              last_seen  = VALUES(last_seen),
              seen_count = seen_count + 1,
              is_alive   = 1
        """
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.executemany(sql, rows)
            conn.commit()
        return len(rows)

    def mark_asset_checked(self, host, type_val, status, alive=True):
        """记录某个资产的最近检测结果"""
        sql = """
            UPDATE Assets
               SET last_check_at = NOW(), last_check_status = %s, is_alive = %s
             WHERE host = %s AND type_val = %s
        """
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (status, 1 if alive else 0, host, type_val))
            conn.commit()

    def mark_asset_dead(self, host, type_val):
        """软删除：资产标记为不可用（保留历史发现时间）"""
        self.mark_asset_checked(host, type_val, "dead", alive=False)

    def start_run(self, run_type, source):
        """开一次扫描批次，返回 run id"""
        sql = "INSERT INTO ScanRuns (run_type, source, started_at) VALUES (%s, %s, NOW())"
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (run_type, source))
            conn.commit()
            return cursor.lastrowid

    def finish_run(self, run_id, hosts_seen=0, findings=0, note=None):
        sql = (
            "UPDATE ScanRuns SET finished_at = NOW(), hosts_seen = %s, "
            "findings = %s, note = %s WHERE id = %s"
        )
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (hosts_seen, findings, note, run_id))
            conn.commit()

    def upsert_host_data(self, host, username, password, type_val, seen_at=None):
        """新增或更新 host 弱口令记录（基于 host 唯一键），同时刷新时间戳"""
        now = seen_at or datetime.now()
        sql = """
            INSERT INTO DefaultPass
                (host, username, password, type_val, first_seen, last_seen,
                 last_check_at, seen_count, is_valid)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1, 1)
            ON DUPLICATE KEY UPDATE
              username      = VALUES(username),
              password      = VALUES(password),
              type_val      = VALUES(type_val),
              last_seen     = VALUES(last_seen),
              last_check_at = VALUES(last_check_at),
              seen_count    = seen_count + 1,
              is_valid      = 1,
              first_seen    = IFNULL(first_seen, VALUES(first_seen))
        """
        params = (host, username, password, type_val, now, now, now)
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    affected = cursor.execute(sql, params)
                conn.commit()
                if affected == 1:
                    return f"✅ 成功新增记录（host={host}）"
                if affected == 2:
                    return f"✅ 成功更新记录（host={host}）"
                return f"✅ 记录已存在，时间戳已刷新（host={host}）"
        except IntegrityError as e:
            return f"❌ 数据错误: {str(e)}"
        except Exception as e:
            return f"❌ 操作失败: {str(e)}"

    def delete_by_host(self, host_value):
        """硬删除（兼容旧行为）"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                affected = cursor.execute("DELETE FROM DefaultPass WHERE host = %s", (host_value,))
                conn.commit()
            if affected > 0:
                result_msg = f"成功删除 {affected} 条记录（host={host_value}）"
            else:
                result_msg = f"未找到 host={host_value} 的记录，无需删除"
            print(result_msg)
            return json.dumps({"result": result_msg, "affected_rows": affected}, ensure_ascii=False, indent=2)
        except Exception as e:
            error_msg = f"删除失败: {str(e)}"
            print(error_msg)
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            return json.dumps({"error": error_msg}, ensure_ascii=False)
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def invalidate_by_host(self, host_value):
        """软删除：口令失效标记，保留记录与历史时间"""
        sql = "UPDATE DefaultPass SET is_valid = 0, last_check_at = NOW() WHERE host = %s"
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                affected = cursor.execute(sql, (host_value,))
            conn.commit()
        return affected

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
