import execjs
import requests
from pyquery import PyQuery as pq


def get_pwd():
    with open('haodou_js.js', 'r', encoding='UTF-8') as f:
        js2 = f.read()
        ctx2 = execjs.compile(js2)
        pwd = ctx2.call("get_pwd", '111111')  # 这里是密码

    return pwd


def get_sso_token():
    url = 'http://login.haodou.com/'
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', 'Connection': 'keep-alive',
        'Cookie': 'PHPSESSID=cg1sinvvc3lejkv3uvv3o61jj0; HDid=1561778611245; product=1; _uab_collina=156179025038866839820592; _wtip=0%7C%2B5; UM_distinctid=16ba1f63de6a2a-0fc5697c844879-e343166-1fa400-16ba1f63de7bae; _ga=GA1.2.626879575.1561790398; _gid=GA1.2.2045726504.1561790398; Hm_lvt_fbb4fdac678166fd7a6f7e50d6e5040c=1561790398; Hm_lpvt_fbb4fdac678166fd7a6f7e50d6e5040c=1561791766; _gat=1',
        'Host': 'login.haodou.com', 'Referer': 'http://www.haodou.com/', 'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'}
    res = requests.get(url, headers=headers)
    doc = pq(res.text)
    sso_token = doc('#sso_token').attr('value')
    print(sso_token)
    return sso_token


def login():
    url = 'http://login.haodou.com/index.php?do=check'
    headers = {'Accept': 'application/json, text/javascript, */*; q=0.01', 'Accept-Encoding': 'gzip, deflate',
               'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', 'Connection': 'keep-alive', 'Content-Length': '340',
               'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
               'Cookie': 'PHPSESSID=cg1sinvvc3lejkv3uvv3o61jj0; HDid=1561778611245; product=1',
               'Host': 'login.haodou.com', 'Origin': 'http://login.haodou.com', 'Referer': 'http://login.haodou.com/',
               'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36',
               'X-Requested-With': 'XMLHttpRequest'}
    password = get_pwd()
    sso_token = get_sso_token()
    data = {
        'account': '188141411252',
        'type': '2',
        'password': password,
        'referer': 'http://www.haodou.com',
        'auto_login': '0',
        'valicode': '',
        'sso_token': sso_token,
    }
    res = requests.post(url, headers=headers, data=data)
    print(res.status_code)
    print(res.text)
    print(res.cookies.get_dict())


if __name__ == '__main__':
    login()

