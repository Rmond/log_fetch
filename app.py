# encoding: utf-8
import json,os,sys

from flask import Flask
from flask import request,render_template,redirect,session

app = Flask(__name__)

def login_check(func):#登录检查装饰器
    def wrapper(*args,**kwargs):
        username = session.get('username',None)
        if not username:
            return redirect('/')
        return func(*args,**kwargs)
    return wrapper

def authenticate(username,password):
    for user in config["info"]:
        if user["username"] == username:
            if user["password"] == password:  # 登录判断
                return user
            else:  # 判断密码是否正确
                return None
    return None

@app.route('/', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate(username,password)
        if user:
            session['username'] = user['username']
            return redirect('/index')
        else:#判断密码是否正确
            return render_template("login.html",msg=u'用户名或密码错误')
    return render_template("login.html")

@app.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    if request.method == 'POST':
        host_info = request.get_json()
        shell='ansible -i hosts '+host_info["host"]+' -m fetch -a "src='+host_info["file_path"]+' dest=/tmp/"'
        result = os.popen(shell).read()
        print(result)
        return result
    else:
        for user in config["info"]:
            if user["username"] == session["username"]:
                hosts = user["hosts"]
        return render_template("index.html", hosts=hosts)

if __name__ == '__main__':
    conf_file = "config.json"
    if os.path.isfile(conf_file):
        with open(conf_file) as config_file:
            config = json.load(config_file)
        app.config["SECRET_KEY"] = 'TPmi4aLWRbyVq8zu9v82dWYW1'
        app.run(host='0.0.0.0', port=5000)
    else:
        print('Config file not exist!')
        sys.exit(0)