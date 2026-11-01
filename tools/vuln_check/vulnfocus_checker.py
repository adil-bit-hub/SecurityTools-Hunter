import requests

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

# vulnfocus默认口令
data = {"username": "admin","password": "admin"}

# DVWA默认口令检测函数
def vulnfocus_checker(host):
    url = f"http://{host}/api/login/"
    headers = {
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return {"host": host, "type": "vulnfocus", "username": "admin", "password": "admin"}
        else:
            return  None
    except :
        return None