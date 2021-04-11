#!/user/bin/python3
# -*- coding = utf-8 -*-
# @Time : 2021/4/11
# @Author : 郑煜辉
# @File : requests
import requests
res = requests.post('http://127.0.0.1:5000/login',json={'username':'test','password':'test'})
print(res.json())
access_token = res.json()['access_token']

header={
    "Authorization": f"Bearer {access_token}"
}
res = requests.get('http://127.0.0.1:5000/protected',headers=header)  # 如果重新获得token则无效
print(res.text)