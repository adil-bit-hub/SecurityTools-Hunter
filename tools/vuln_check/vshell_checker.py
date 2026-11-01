import requests

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

data = {'username': 'admin','password': 'qwe123qwe'}
# 检查Vshell的默认账密
def vshell_checker(host):
    url = f"http://{host}/login/verify"

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Authorization': 'Basic YWRtaW46cXdlMTIzcXdl',
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest'
    }
    req = requests.post(url, headers=headers, data=data,timeout=20).json()
    if (req["status"] == 1):
        return {"host": host, "type": "vshell", "username": "admin", "password": "qwe123qwe"}
    else:    
        return None