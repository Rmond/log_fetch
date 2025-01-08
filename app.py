import os,sys,datetime,sqlite3,json
from functools import wraps

from flask import Flask,request,render_template,redirect,session,send_from_directory,g,jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = 'TPmi4aLWRbyVq8zu9v82dWYW1'

# 添加URL前缀配置
URL_PREFIX = '/log_fetch'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('users.db')
        g.db.row_factory = sqlite3.Row 
    return g.db

@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()

def login_check(func):#登录检查装饰器
    @wraps(func)
    def wrapper(*args,**kwargs):
        username = session.get('username',None)
        if not username:
            return redirect(URL_PREFIX + '/')
        return func(*args,**kwargs)
    return wrapper

def authenticate(username, password):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', 
                     (username,)).fetchone()
    if user and user['password'] == password:
        return dict(user)
    return None

@app.route(URL_PREFIX + '/', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(request.url)
        user = authenticate(username,password)
        if user:
            if user["active"]:
                session['username'] = user['username']
                if user['is_admin']:  # 管理员跳转到管理后台
                    return redirect(URL_PREFIX + '/admin')
                return redirect(URL_PREFIX + '/index')  # 普通用户跳转到原始页面
            else:
                return render_template("login.html", msg=u'此用户已被锁定请联系管理员解锁')
        else:
            return render_template("login.html", msg=u'用户名或密码错误')
    return render_template("login.html")

@app.route(URL_PREFIX + '/index', methods=['POST', 'GET'])
@login_check
def index():
    if request.method == 'POST':
        host = request.form["host"]
        file_path = request.form["file_path"]
        if "home" not in file_path or "/../" in file_path:
            db = get_db()
            db.execute('UPDATE users SET active = ? WHERE username = ?',
                      (False, session["username"]))
            db.commit()
            session.clear()
            return "invalid path,you had been baned"
        shell='ansible -i hosts '+host+' -m fetch -a "src='+file_path+' dest=/tmp/"'
        result = os.popen(shell).read().split("=>")
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"-->"+session['username']+" download "+host+" file:"+file_path)
        res_flag = result[0]
        if "FAILED" in res_flag:
            return "file not found！"
        else:
            try:
                res_stdout = json.loads(result[1])
                local_path,filename = os.path.split(res_stdout["dest"])
                return send_from_directory(local_path, filename=filename, as_attachment=True)
            except json.JSONDecodeError:
                return "Invalid response format"
    else:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?',
                         (session["username"],)).fetchone()
        hosts = db.execute('SELECT host FROM user_hosts WHERE username = ?',
                          (session["username"],)).fetchall()
        hosts = [host['host'] for host in hosts]
        return render_template("index.html", hosts=hosts, is_admin=user['is_admin'])

@app.route(URL_PREFIX + '/filter', methods=['POST'])
@login_check
def filter():
    if request.method == 'POST':
        host = request.form["host"]
        file_path = request.form["file_path"]
        key = request.form["key"]
        if "home" not in file_path or "/../" in file_path:
            db = get_db()
            db.execute('UPDATE users SET active = ? WHERE username = ?',
                      (False, session["username"]))
            db.commit()
            session.clear()
            return "invalid path,you had been baned"
        shell = 'ansible -i hosts '+host+' -m shell -a "grep -rn '+key+' '+file_path+'"'
        print(shell)
        result = os.popen(shell).read().split('>>')
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"-->"+session['username']+host+" filter "+key+" file:"+file_path)
        try:
            res_flag = result[1] if len(result) > 1 else ""
            return jsonify({"res": res_flag})
        except Exception as e:
            return jsonify({"res": str(e)})

@app.route(URL_PREFIX + '/admin')
@login_check
def admin_index():
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE username = ?',
                     (session["username"],)).fetchone()
    if not user['is_admin']:
        return redirect(URL_PREFIX + '/index')
    
    # 获取统计数据
    user_count = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    host_count = db.execute('SELECT COUNT(DISTINCT host) as count FROM user_hosts').fetchone()['count']
    
    return render_template('admin/index.html', 
                         user_count=user_count,
                         host_count=host_count)

@app.route(URL_PREFIX + '/admin/users', methods=['GET', 'POST'])
@login_check
def admin_users():
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE username = ?',
                     (session["username"],)).fetchone()
    if not user['is_admin']:
        return redirect(URL_PREFIX + '/index')
    
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        
        if action == 'add':
            password = request.form.get('password')
            try:
                db.execute('''INSERT INTO users 
                             (username, password, active, is_admin, created_at) 
                             VALUES (?, ?, ?, ?, ?)''',
                          (username, password, True, False, 
                           datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                db.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"status": "error", "message": "用户名已存在"}), 400
                
        elif action == 'delete':
            db.execute('DELETE FROM user_hosts WHERE username = ?', (username,))
            db.execute('DELETE FROM users WHERE username = ? AND NOT is_admin', 
                      (username,))
            db.commit()
            return jsonify({"status": "success"})
            
        elif action == 'toggle_active':
            db.execute('''UPDATE users SET active = NOT active 
                         WHERE username = ? AND NOT is_admin''', 
                      (username,))
            db.commit()
            return jsonify({"status": "success"})
        
        elif action == 'edit':
            old_username = request.form.get('old_username')
            username = request.form.get('username')
            password = request.form.get('password')
            
            db = get_db()
            if password:
                db.execute('''UPDATE users SET username = ?, password = ? 
                             WHERE username = ? AND NOT is_admin''',
                          (username, password, old_username))
            else:
                db.execute('''UPDATE users SET username = ? 
                             WHERE username = ? AND NOT is_admin''',
                          (username, old_username))
            
            if old_username != username:
                db.execute('UPDATE user_hosts SET username = ? WHERE username = ?',
                          (username, old_username))
            
            db.commit()
            return jsonify({"status": "success"})
    
    # GET请求处理
    users = db.execute('''SELECT username, active, created_at 
                         FROM users WHERE username != "admin"
                         ORDER BY created_at DESC''').fetchall()
    return render_template('admin/users.html', users=users)

@app.route(URL_PREFIX + '/admin/permissions', methods=['GET', 'POST'])
@login_check
def admin_permissions():
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE username = ?',
                     (session["username"],)).fetchone()
    if not user['is_admin']:
        return redirect(URL_PREFIX + '/index')
    
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        host = request.form.get('host')
        
        if action == 'add':
            try:
                db.execute('''INSERT INTO user_hosts (username, host, created_at) 
                             VALUES (?, ?, ?)''',
                          (username, host, 
                           datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                db.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"status": "error", "message": "该授权已存在"}), 400
                
        elif action == 'delete':
            db.execute('DELETE FROM user_hosts WHERE username = ? AND host = ?',
                      (username, host))
            db.commit()
            return jsonify({"status": "success"})
        
        elif action == 'update':
            username = request.form.get('username')
            hosts = request.form.getlist('hosts[]')
            
            db = get_db()
            db.execute('DELETE FROM user_hosts WHERE username = ?', (username,))
            for host in hosts:
                db.execute('INSERT INTO user_hosts (username, host) VALUES (?, ?)', (username, host))
            db.commit()
            return jsonify({"status": "success"})
    
    # 修改SQL查询以正确计算主机数量
    user_permissions = db.execute('''
        SELECT 
            u.username, 
            GROUP_CONCAT(uh.host) as hosts,
            COUNT(DISTINCT uh.host) as host_count
        FROM users u
        LEFT JOIN user_hosts uh ON u.username = uh.username
        WHERE NOT u.is_admin
        GROUP BY u.username
        ORDER BY u.created_at DESC
    ''').fetchall()
    
    # 更新字典列表转换逻辑
    user_permissions = [
        {'username': row['username'], 
         'hosts': row['hosts'] if row['hosts'] else '无授权主机',
         'host_count': row['host_count']} 
        for row in user_permissions
    ]
    
    users = db.execute('SELECT username FROM users WHERE NOT is_admin').fetchall()
    hosts = db.execute('SELECT host FROM hosts').fetchall()
    all_hosts = [host['host'] for host in hosts]
    
    return render_template('admin/permissions.html',
                         user_permissions=user_permissions,
                         users=users,
                         hosts=hosts,
                         all_hosts=all_hosts)

@app.route(URL_PREFIX + '/admin/permissions/user_hosts')
@login_check
def get_user_hosts():
    username = request.args.get('username')
    db = get_db()
    hosts = db.execute('SELECT host FROM user_hosts WHERE username = ?',
                      (username,)).fetchall()
    return jsonify({
        'user_hosts': [h['host'] for h in hosts]
    })

# 修改主机管理路由
@app.route(URL_PREFIX + '/admin/hosts', methods=['GET', 'POST'])
@login_check
def admin_hosts():
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE username = ?',
                     (session["username"],)).fetchone()
    if not user['is_admin']:
        return redirect(URL_PREFIX + '/index')
    
    if request.method == 'POST':
        action = request.form.get('action')
        host = request.form.get('host')
        description = request.form.get('description', '')
        
        if action == 'add':
            try:
                db.execute('''INSERT INTO hosts (host, description) 
                            VALUES (?, ?)''',
                         (host, description))
                db.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"status": "error", "message": "主机已存在"}), 400
        elif action == 'delete':
            db.execute('DELETE FROM user_hosts WHERE host = ?', (host,))
            db.execute('DELETE FROM hosts WHERE host = ?', (host,))
            db.commit()
            return jsonify({"status": "success"})
        elif action == 'edit':
            db.execute('UPDATE hosts SET description = ? WHERE host = ?',
                      (description, host))
            db.commit()
            return jsonify({"status": "success"})
    
    # GET请求获取数据
    hosts = db.execute('''
        SELECT h.host, h.description, h.created_at,
               COUNT(uh.username) as user_count
        FROM hosts h
        LEFT JOIN user_hosts uh ON h.host = uh.host
        GROUP BY h.host
        ORDER BY h.created_at DESC
    ''').fetchall()
    
    return render_template('admin/hosts.html', hosts=hosts)

@app.route(URL_PREFIX + '/send', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':
        post_data = request.get_data()
        print(post_data)
        print(request.url)
        return 'success'

@app.route(URL_PREFIX + '/logout')
def logout():
    session.clear()
    return redirect(URL_PREFIX + '/')

if __name__ == '__main__':
    if os.path.isfile('users.db'):
        app.run(host='0.0.0.0', port=5000)
    else:
        print('Database file not exist! Please run init_db.py first')
        sys.exit(0)