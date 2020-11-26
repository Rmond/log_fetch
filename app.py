# encoding: utf-8
import json,os,sys,datetime
from functools import wraps

from flask import Flask
from flask import request,render_template,redirect,session,send_from_directory,g

app = Flask(__name__)
app.config["SECRET_KEY"] = 'TPmi4aLWRbyVq8zu9v82dWYW1'
conf_file = "config.json"
if os.path.isfile(conf_file):
    with open(conf_file) as config_file:
        config = json.load(config_file)
else:
    print('Config file not exist!')
    sys.exit(0)


def login_check(func):#登录检查装饰器
    @wraps(func)
    def wrapper(*args,**kwargs):
        username = session.get('username',None)
        if not username:
            return redirect('/')
        return func(*args,**kwargs)
    return wrapper

def authenticate(username,password):
    with open(conf_file) as config_file:
        config = json.load(config_file)
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
            if user["active"]:
                session['username'] = user['username']
                return redirect('/index')
            else:
                return render_template("login.html", msg=u'此用户已被锁定请联系管理员解锁')
        else:#判断密码是否正确
            return render_template("login.html", msg=u'用户名或密码错误')
    return render_template("login.html")

@app.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    if request.method == 'POST':
        host = request.form["host"]
        file_path = request.form["file_path"]
        if "home" not in file_path or "/../" in file_path:
            for user in config["info"]:
                if user["username"] == session["username"]:
                    user["active"] = False
            with open(conf_file,'w') as f:
                f.write(json.dumps(config))
            session.clear()
            return "invalid path,you had been baned"
        shell='ansible -i hosts '+host+' -m fetch -a "src='+file_path+' dest=/tmp/"'
        result = os.popen(shell).read().split("=>")
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"-->"+session['username']+" download "+host+" file:"+file_path)
        res_flag = result[0]
        if "FAILED" in res_flag:
            return "file not found！"
        else:
            res_stdout = json.loads(result[1])
            local_path,filename = os.path.split(res_stdout["dest"])
            return send_from_directory(local_path, filename=filename, as_attachment=True)
        #return host_info
    else:
        for user in config["info"]:
            if user["username"] == session["username"]:
                hosts = user["hosts"]
        return render_template("index.html", hosts=hosts)

@app.route('/filter', methods=['POST'])
@login_check
def filter():
    if request.method == 'POST':
        host = request.form["host"]
        file_path = request.form["file_path"]
        key = request.form["key"]
        if "home" not in file_path or "/../" in file_path:
            for user in config["info"]:
                if user["username"] == session["username"]:
                    user["active"] = False
            with open(conf_file,'w') as f:
                f.write(json.dumps(config))
            session.clear()
            return "invalid path,you had been baned"
        shell='ansible -i hosts '+host+' -m shell -a "grep -rn '+key+' '+file_path+'"'
        result = os.popen(shell).read().split("=>")
        #result = shell
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"-->"+session['username']+host+" filter "+key+" file:"+file_path)
        res_flag = result[0]
        return res_flag

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