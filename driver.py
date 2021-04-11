#!/user/bin/python3
# -*- coding = utf-8 -*-
# @Time : 2021/4/11
# @Author : 郑煜辉
# @File : driver

import flask, json
from flask import request

server = flask.Flask(__name__)


@server.route('/login', methods=['get', 'post'])
def login():
    username = request.values.get('name')
    pwd = request.values.get('pwd')
    if username and pwd:
        if username == 'xiaoming' and pwd == '123':
            resu = {'code': 200, 'message': '登录成功', 'token': '165AS5a612q547'}
            return json.dump(resu, ensure_ascii=False)
        else:
            resu = {'code': -1, 'message': '账号密码错误'}
            return json.dump(resu, ensure_ascii=False)
    else:
        resu = {'code': 10001, 'message': '参数不为空'}
        return json.dump(resu, ensure_ascii=False)


if __name__ == '__main__':
    server.run(debug=True,port=8888,host='127.0.0.1')
