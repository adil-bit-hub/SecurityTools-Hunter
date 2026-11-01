import requests
from bs4 import BeautifulSoup

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

def extract_csrf_token(html):
    """从登录页面提取 CSRF 令牌"""
    soup = BeautifulSoup(html, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    return token_input["value"] if token_input else None

def dvwa_checker(host, username="admin", password="password"):
    """尝试使用提供的用户名和密码登录"""
    session = requests.Session()
    
    url = f"http://{host}/login.php"

    try:
        # 访问登录页面获取 CSRF 令牌
        login_page = session.get(url)
        csrf_token = extract_csrf_token(login_page.text)
        
        if not csrf_token:
            # print(f"{host}: 无法获取 CSRF 令牌，登录可能失败！")
            return None
        
        # 构造登录请求数据
        data = {
            "username": username,
            "password": password,
            "user_token": csrf_token,
            "Login": "Login"
        }
        
        # 发送 POST 请求进行登录
        response = session.post(url, data=data,timeout=10)
        
        # 检查是否成功登录
        if "Welcome" in response.text or "DVWA Security" in response.text:
            return {"host": host, "type": "dvwa", "username": "admin", "password": "password"}
        else:
            return None
    except Exception as e:
        return None