import requests

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

data = {'username': 'admin','password': 'Admin@tenable123'}
# 检查Nessus的默认账密
def nessus_checker(host):
    url = f"https://{host}/session"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Content-Type': 'application/json',
    }
    req = requests.post(url, headers=headers, json=data,verify=False,timeout=10).json()
    if (req["token"] != ""):
        return {"host": host, "type": "nessus", "username": "admin", "password": "Admin@tenable123"}
    else:    
        return None 
