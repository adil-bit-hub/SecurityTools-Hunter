-- SafeToolHunter 数据库结构（MySQL 5.7+/8.x、MariaDB 10.4+ 通用）
-- 程序启动时会自动执行同样的 DDL（tools/db.py: ensure_schema），
-- 这里保留一份可手工执行的版本，便于审计或初始化全新库。

CREATE DATABASE IF NOT EXISTS readteam
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

-- 资产表：记录每个 (host, type) 的首次发现与最近一次发现时间
CREATE TABLE IF NOT EXISTS Assets (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host          VARCHAR(255)    NOT NULL,
  type_val      VARCHAR(64)     NOT NULL,
  first_seen    DATETIME        NOT NULL COMMENT '首次发现时间',
  last_seen     DATETIME        NOT NULL COMMENT '最近一次被 FOFA 发现的时间',
  seen_count    INT UNSIGNED    NOT NULL DEFAULT 1 COMMENT '累计被搜索到次数',
  last_check_at DATETIME        NULL COMMENT '最近一次检测时间',
  last_check_status VARCHAR(32) NULL COMMENT 'cred_ok / cred_fail / dead / error',
  is_alive      TINYINT(1)      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uk_host_type (host, type_val),
  KEY idx_last_seen (last_seen),
  KEY idx_type_last_seen (type_val, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 弱口令命中表
CREATE TABLE IF NOT EXISTS DefaultPass (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host          VARCHAR(255)    NOT NULL,
  username      VARCHAR(255)    NULL,
  password      VARCHAR(255)    NULL,
  type_val      VARCHAR(64)     NULL,
  first_seen    DATETIME        NULL,
  last_seen     DATETIME        NULL,
  last_check_at DATETIME        NULL,
  seen_count    INT UNSIGNED    NOT NULL DEFAULT 1,
  is_valid      TINYINT(1)      NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uk_host (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 扫描批次表
CREATE TABLE IF NOT EXISTS ScanRuns (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_type    VARCHAR(64)     NOT NULL,
  source      VARCHAR(16)     NOT NULL,
  started_at  DATETIME        NOT NULL,
  finished_at DATETIME        NULL,
  hosts_seen  INT UNSIGNED    NOT NULL DEFAULT 0,
  findings    INT UNSIGNED    NOT NULL DEFAULT 0,
  note        VARCHAR(255)    NULL,
  PRIMARY KEY (id),
  KEY idx_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 按最新发现时间倒序看资产
CREATE OR REPLACE VIEW v_assets_latest AS
SELECT host, type_val, first_seen, last_seen,
       TIMESTAMPDIFF(HOUR, last_seen, NOW()) AS age_hours,
       seen_count, last_check_status, is_alive
FROM Assets
ORDER BY last_seen DESC;
