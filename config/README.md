# config/ 说明

本目录存放运行所需的凭据配置。**真实配置不入库**，仓库只提供 `*.example.json` 模板。

## 初始化

```bash
cp config/dbconfig.example.json    config/dbconfig.json
cp config/fofaconfig.example.json  config/fofaconfig.json
```

然后编辑两个文件填入真实值。

## dbconfig.json — MySQL 连接

| 字段 | 说明 |
| --- | --- |
| `host` / `port` | MySQL 地址与端口 |
| `user` / `password` | 数据库账号密码 |
| `database` | 库名（默认 `readteam`） |
| `charset` | 建议 `utf8mb4` |
| `connect_timeout` | 连接超时（秒） |
| `autocommit` | 建议 `true` |

建库：

```sql
CREATE DATABASE readteam DEFAULT CHARSET utf8mb4;
```

## fofaconfig.json — FOFA API

| 字段 | 说明 |
| --- | --- |
| `base_url` | FOFA 搜索接口，一般无需修改 |
| `key` | 你的 FOFA API Key |

> ⚠️ 这两个文件已在 `.gitignore` 中排除。若曾误提交，请立即更换数据库密码和 FOFA Key。
