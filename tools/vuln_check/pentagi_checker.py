import requests
from urllib.parse import urlparse

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

# PentAGI默认凭据
DEFAULT_EMAIL = "admin@pentagi.com"
DEFAULT_PASSWORD = "admin"
DEFAULT_PORT = 8443  # PentAGI默认Web端口

# 通用请求头，Origin/Referer按目标站点动态生成
COMMON_HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'content-type': 'application/json',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
}


def _ensure_port(host):
    """剥离协议与路径，host无端口时补齐PentAGI默认端口8443"""
    for prefix in ('https://', 'http://'):
        if host.startswith(prefix):
            host = host[len(prefix):]
    if '/' in host:
        host = host.split('/')[0]
    # 已显式携带端口的host原样返回
    try:
        if urlparse(f"//{host}").port is not None:
            return host
    except ValueError:
        pass
    return f"{host}:{DEFAULT_PORT}"


# 检查PentAGI的默认账密
def pentagi_checker(host):
    host = _ensure_port(host)
    url = f"https://{host}/api/v1/auth/login"

    headers = COMMON_HEADERS.copy()
    headers['origin'] = f"https://{host}"
    headers['referer'] = f"https://{host}/login?returnUrl=%2Fdashboard"

    data = {"mail": DEFAULT_EMAIL, "password": DEFAULT_PASSWORD}

    try:
        req = requests.post(url, headers=headers, json=data, verify=False, timeout=10, allow_redirects=False)
        if req.status_code != 200:
            return None
        resp = req.json()
        # PentAGI登录成功会返回token/accessToken等认证信息
        if 'token' in resp or 'accessToken' in resp or resp.get('message') == 'Login successful' or resp.get('status') == 'success':
            return {"host": host, "type": "pentagi", "username": DEFAULT_EMAIL, "password": DEFAULT_PASSWORD}
    except Exception:
        return None
    return None