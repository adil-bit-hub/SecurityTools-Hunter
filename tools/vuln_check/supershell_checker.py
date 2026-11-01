import requests

#禁用requests的安全警告，不开启则会出现很多https报警,对结果无影响
requests.packages.urllib3.disable_warnings()

data = {"username": "tdragon6","password": "tdragon6"}
# 检查SuperShell默认账密
def supershell_checker(host):
    req = requests.post(f"http://{host}/supershell/login/auth",json=data,timeout=20).json()
    if (req["result"] == "success"):
        return {"host": host, "type": "supershell", "username": "tdragon6", "password": "tdragon6"}
    else:    
        return None 
