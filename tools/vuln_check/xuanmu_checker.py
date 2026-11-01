import requests

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

data = {'email': 'admin@admin.com', 'password': 'admin123'}
# 检查XuanMu-RedTeam-Agent的默认账密
def xuanmu_checker(host):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Content-Type': 'application/json',
    }

    # 优先按抓包确认的HTTP探测，异常或非200时回退HTTPS
    for scheme in ('http', 'https'):
        url = f"{scheme}://{host}/api/system-users/login"
        try:
            req = requests.post(url, headers=headers, json=data, verify=False, timeout=10)
        except Exception:
            continue
        try:
            resp = req.json()
        except Exception:
            continue
        # 登录成功：code==200 且返回 token
        if resp.get("code") == 200 and resp.get("data", {}).get("token"):
            return {"host": host, "type": "xuanmu", "username": "admin@admin.com", "password": "admin123"}
        # 目标存活且已明确返回业务失败，无需再尝试另一种协议
        if req.status_code == 200:
            return None
    return None