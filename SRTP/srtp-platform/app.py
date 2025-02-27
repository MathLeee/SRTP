import sqlite3
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from flask_mail import Mail, Message
from itsdangerous import TimedSerializer
import json
import os
from werkzeug.utils import secure_filename
from functools import wraps
from decimal import Decimal
import decimal
from flask_wtf.csrf import CSRFProtect
import bleach

app = Flask(__name__)
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),  # 延长会话时间到30天
    SESSION_COOKIE_SECURE=False,  # 开发环境下设置为False，生产环境应该设置为True
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='srtp_session',  # 自定义session cookie名称
    SESSION_COOKIE_PATH='/',  # 设置cookie路径
    REMEMBER_COOKIE_DURATION=timedelta(days=30),  # 记住我的持续时间
    REMEMBER_COOKIE_SECURE=False,  # 开发环境下设置为False，生产环境应该设置为True
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax'
)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)

# 使用绝对路径
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static/uploads')
DATABASE_PATH = os.path.join(BASE_DIR, 'srtp.db')

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Mail configuration
app.config['MAIL_SERVER'] = 'https://mail.163.com/'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lxy200679@163.com'
app.config['MAIL_PASSWORD'] = '200679aa'
mail = Mail(app)

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  public_key TEXT,
                  reset_token TEXT,
                  reset_token_expiry DATETIME,
                  email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS items
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT,
                  description TEXT,
                  price REAL,
                  seller_id INTEGER,
                  encrypted_contact TEXT,
                  created_at DATETIME,
                  image_path TEXT,
                  status TEXT DEFAULT 'available')''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  item_id INTEGER,
                  seller_id INTEGER,
                  buyer_id INTEGER,
                  signature TEXT,
                  transaction_data TEXT,
                  status TEXT,
                  created_at DATETIME)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER,
                  receiver_id INTEGER,
                  item_id INTEGER,
                  content TEXT,
                  created_at DATETIME,
                  is_read INTEGER DEFAULT 0,
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  FOREIGN KEY (receiver_id) REFERENCES users (id),
                  FOREIGN KEY (item_id) REFERENCES items (id))''')
    conn.commit()
    conn.close()

# 在所有路由之前添加会话检查装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        app.logger.info(f"Current session: {dict(session)}")  # 添加日志
        if 'user_id' not in session:
            app.logger.warning("User not logged in, redirecting to login page")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Generate RSA key pair
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

# Load public key from PEM string
def load_public_key(public_key_pem):
    return serialization.load_pem_public_key(public_key_pem.encode())

# Sign data with private key
def sign_data(private_key_pem, data):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    
    # Convert data to bytes if it's not already
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

# Verify signature with public key
def verify_signature(public_key_pem, data, signature):
    public_key = load_public_key(public_key_pem)
    signature_bytes = base64.b64decode(signature)
    
    # Convert data to bytes if it's not already
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    
    try:
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Register user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if len(username) < 4 or not username.isalnum():
            return jsonify({'status': 'error', 'message': '无效的用户名，至少4个字符且只能包含字母和数字'}), 400
        
        password = request.form['password']
        email = request.form.get('email', '')
        
        if len(password) < 8:
            return jsonify({'status': 'error', 'message': '密码至少需要8个字符'}), 400
            
        hashed_password = generate_password_hash(password)
        private_pem, public_pem = generate_rsa_keypair()
        
        try:
            conn = sqlite3.connect(DATABASE_PATH, timeout=10)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
            if c.fetchone()[0] > 0:
                return jsonify({'status': 'error', 'message': '用户名已存在'}), 400
                
            c.execute("INSERT INTO users (username, password, public_key, email) VALUES (?, ?, ?, ?)", 
                     (username, hashed_password, public_pem, email))
            conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
        finally:
            conn.close()
            
        # 私钥需要安全地提供给用户保存
        return jsonify({
            'status': 'success', 
            'message': '注册成功，请安全保存您的私钥',
            'private_key': private_pem
        })
    else:
        return render_template('register.html')

# Login user
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember', False)  # 获取"记住我"选项
        app.logger.info(f"Login attempt for user: {username}")
        
        try:
            conn = sqlite3.connect(DATABASE_PATH, timeout=10)
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE username=?", (username,))
            user = c.fetchone()
            
            if user and check_password_hash(user[1], password):
                session.clear()  # 清除旧的会话数据
                session.permanent = True  # 设置会话为永久性
                session['user_id'] = user[0]
                session['username'] = username
                session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                if remember:  # 如果用户选择"记住我"
                    # 设置更长的会话过期时间
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)
                
                response = make_response(jsonify({
                    'status': 'success', 
                    'message': '登录成功',
                    'redirect': url_for('index')
                }))
                
                # 设置额外的cookie来加强会话持久性
                response.set_cookie(
                    'remember_token',
                    value=username,
                    max_age=30 * 24 * 60 * 60,  # 30天
                    secure=False,  # 开发环境为False
                    httponly=True,
                    samesite='Lax'
                )
                
                app.logger.info(f"Login successful. Session: {dict(session)}")
                return response
            else:
                return jsonify({'status': 'error', 'message': '用户名或密码错误'}), 400
        except sqlite3.OperationalError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
        finally:
            conn.close()
    else:
        return render_template('login.html')

# Logout user
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

s = TimedSerializer(app.secret_key)
# Forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT id, email FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user and user[1]:  # 确保用户存在且有邮箱
            token = s.dumps(username, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('密码重置请求', sender='noreply@example.com', recipients=[user[1]])
            msg.body = f'请点击以下链接重置密码: {reset_url}'
            mail.send(msg)
            c.execute("UPDATE users SET reset_token=?, reset_token_expiry=? WHERE id=?", 
                     (token, datetime.now(timezone.utc) + timedelta(hours=1), user[0]))
            conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': '如果用户名已注册，一封重置密码的邮件已发送到关联邮箱。'})
    return render_template('forgot_password.html')

# Reset password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        username = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'status': 'error', 'message': '重置链接无效或已过期。'}), 400

    if request.method == 'POST':
        new_password = request.form['password']
        if len(new_password) < 8:
            return jsonify({'status': 'error', 'message': '密码至少需要8个字符'}), 400
            
        hashed_password = generate_password_hash(new_password)
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET password=?, reset_token=NULL, reset_token_expiry=NULL WHERE username=?", 
                 (hashed_password, username))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': '密码重置成功，请使用新密码登录。'})
    return render_template('reset_password.html', token=token)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Post new item
@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_item():
    if request.method == 'POST':
        try:
            price = Decimal(request.form['price'])
            if price <= 0 or price > Decimal('999999999'):
                return jsonify({'status': 'error', 'message': '无效的价格范围'}), 400
            # 格式化价格为两位小数
            formatted_price = "{:.2f}".format(price)
        except (ValueError, decimal.InvalidOperation):
            return jsonify({'status': 'error', 'message': '无效的价格格式'}), 400

# Browse items
@app.route('/items')
def browse_items():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT items.*, users.username as seller_name 
                FROM items 
                JOIN users ON items.seller_id = users.id 
                WHERE items.status = 'available' 
                ORDER BY items.created_at DESC''')
    items = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('browse.html', items=items)

# View item details
@app.route('/item/<int:item_id>')
def view_item(item_id):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT items.*, users.username as seller_name 
                FROM items 
                JOIN users ON items.seller_id = users.id 
                WHERE items.id = ?''', (item_id,))
    result = c.fetchone()
    item = dict(result) if result else None
    conn.close()
    
    if not item:
        return render_template('error.html', message='商品不存在')
        
    return render_template('item_detail.html', item=item)

# Initiate transaction
@app.route('/buy/<int:item_id>', methods=['POST'])
def buy_item(item_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    # 验证是否提供了签名和私钥
    signature = request.form.get('signature')
    transaction_data = request.form.get('transaction_data')
    
    if not signature or not transaction_data:
        return jsonify({'status': 'error', 'message': '缺少签名或交易数据'}), 400
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 检查商品是否存在且可购买
    c.execute("SELECT seller_id, status FROM items WHERE id=?", (item_id,))
    item = c.fetchone()
    
    if not item:
        conn.close()
        return jsonify({'status': 'error', 'message': '商品不存在'}), 404
        
    if item[1] != 'available':
        conn.close()
        return jsonify({'status': 'error', 'message': '商品已售出或不可用'}), 400
        
    if item[0] == session['user_id']:
        conn.close()
        return jsonify({'status': 'error', 'message': '不能购买自己的商品'}), 400
    
    # 获取买家公钥用于验证签名
    c.execute("SELECT public_key FROM users WHERE id=?", (session['user_id'],))
    buyer = c.fetchone()
    if not buyer:
        conn.close()
        return jsonify({'status': 'error', 'message': '买家信息有误'}), 400
        
    buyer_public_key = buyer[0]
    
    # 验证签名
    is_valid = verify_signature(buyer_public_key, transaction_data, signature)
    
    if not is_valid:
        conn.close()
        return jsonify({'status': 'error', 'message': '签名验证失败'}), 400
    
    # 创建交易记录
    c.execute('''INSERT INTO transactions 
                (item_id, seller_id, buyer_id, signature, transaction_data, status, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                (item_id, item[0], session['user_id'], signature, transaction_data,
                 'pending', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    # 更新商品状态
    c.execute("UPDATE items SET status = 'pending' WHERE id = ?", (item_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': '交易已发起，等待卖家确认'})

# Confirm transaction (seller side)
@app.route('/confirm_transaction/<int:transaction_id>', methods=['POST'])
def confirm_transaction(transaction_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 检查交易是否存在且卖家是当前用户
    c.execute('''SELECT transactions.*, items.id as item_id 
                FROM transactions 
                JOIN items ON transactions.item_id = items.id 
                WHERE transactions.id = ? AND transactions.seller_id = ?''', 
                (transaction_id, session['user_id']))
    transaction = c.fetchone()
    
    if not transaction:
        conn.close()
        return jsonify({'status': 'error', 'message': '交易不存在或您无权操作'}), 404
        
    if transaction[6] != 'pending':
        conn.close()
        return jsonify({'status': 'error', 'message': '交易状态不支持此操作'}), 400
    
    # 更新交易和商品状态
    c.execute("UPDATE transactions SET status = 'completed' WHERE id = ?", (transaction_id,))
    c.execute("UPDATE items SET status = 'sold' WHERE id = ?", (transaction[7],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': '交易已确认完成'})

# Cancel transaction
@app.route('/cancel_transaction/<int:transaction_id>', methods=['POST'])
def cancel_transaction(transaction_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 检查交易是否存在且用户是买家或卖家
    c.execute('''SELECT * FROM transactions 
                WHERE id = ? AND (seller_id = ? OR buyer_id = ?)''', 
                (transaction_id, session['user_id'], session['user_id']))
    transaction = c.fetchone()
    
    if not transaction:
        conn.close()
        return jsonify({'status': 'error', 'message': '交易不存在或您无权操作'}), 404
        
    if transaction[6] != 'pending':
        conn.close()
        return jsonify({'status': 'error', 'message': '交易状态不支持此操作'}), 400
    
    # 更新交易和商品状态
    c.execute("UPDATE transactions SET status = 'cancelled' WHERE id = ?", (transaction_id,))
    c.execute("UPDATE items SET status = 'available' WHERE id = ?", (transaction[1],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': '交易已取消'})

# My items
@app.route('/my_items')
def my_items():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM items WHERE seller_id = ? ORDER BY created_at DESC", (session['user_id'],))
    items = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('my_items.html', items=items)

# My transactions
@app.route('/my_transactions')
def my_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # 查询作为卖家的交易
    c.execute('''SELECT t.*, i.title, u.username as buyer_name 
                FROM transactions t 
                JOIN items i ON t.item_id = i.id 
                JOIN users u ON t.buyer_id = u.id 
                WHERE t.seller_id = ? 
                ORDER BY t.created_at DESC''', (session['user_id'],))
    selling_transactions = [dict(row) for row in c.fetchall()]
    
    # 查询作为买家的交易
    c.execute('''SELECT t.*, i.title, u.username as seller_name 
                FROM transactions t 
                JOIN items i ON t.item_id = i.id 
                JOIN users u ON t.seller_id = u.id 
                WHERE t.buyer_id = ? 
                ORDER BY t.created_at DESC''', (session['user_id'],))
    buying_transactions = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return render_template('my_transactions.html', 
                          selling_transactions=selling_transactions,
                          buying_transactions=buying_transactions)

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Index page
@app.route('/')
def index():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT items.*, users.username as seller_name 
                FROM items 
                JOIN users ON items.seller_id = users.id 
                WHERE items.status = 'available' 
                ORDER BY items.created_at DESC 
                LIMIT 10''')
    recent_items = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('index.html', recent_items=recent_items)

# Login page
@app.route('/login_page')
def login_page():
    return render_template('login.html')

# Register page
@app.route('/register_page')
def register_page():
    return render_template('register.html')

# Delete item
@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 验证是否是商品所有者
    c.execute("SELECT seller_id, status FROM items WHERE id = ?", (item_id,))
    item = c.fetchone()
    
    if not item:
        conn.close()
        return jsonify({'status': 'error', 'message': '商品不存在'}), 404
        
    if item[0] != session['user_id']:
        conn.close()
        return jsonify({'status': 'error', 'message': '无权删除此商品'}), 403
        
    if item[1] != 'available':
        conn.close()
        return jsonify({'status': 'error', 'message': '商品处于交易中或已售出，无法删除'}), 400
    
    # 删除商品
    c.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': '商品已成功删除'})

# 编辑商品
@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # 检查商品是否存在且属于当前用户
    c.execute("SELECT * FROM items WHERE id = ? AND seller_id = ?", (item_id, session['user_id']))
    item = c.fetchone()
    
    if not item:
        conn.close()
        return render_template('error.html', message='商品不存在或您无权编辑')
    
    item = dict(item)
    
    if request.method == 'POST':
        # 如果商品已售出或正在交易中，则不允许编辑
        if item['status'] != 'available':
            conn.close()
            return jsonify({'status': 'error', 'message': '商品处于交易中或已售出，无法编辑'}), 400
            
        title = bleach.clean(request.form['title'])
        description = bleach.clean(request.form['description'])
        price = float(request.form['price'])
        contact_info = request.form['contact_info']
        
        # 处理图片上传
        image_path = item['image_path']  # 默认保持原图片
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                # 删除旧图片
                if image_path and os.path.exists(os.path.join('static', image_path)):
                    try:
                        os.remove(os.path.join('static', image_path))
                    except:
                        pass
                
                # 保存新图片
                if allowed_file(image.filename):
                    if len(image.read()) > MAX_FILE_SIZE:
                        return jsonify({'status': 'error', 'message': '文件大小超过限制'}), 400
                    image.seek(0)  # 重置文件指针
                    ext = image.filename.split('.')[-1]
                    filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{session['user_id']}.{ext}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(file_path)
                    image_path = f"uploads/{filename}"
        
        # 更新商品信息
        c.execute('''UPDATE items 
                    SET title=?, description=?, price=?, encrypted_contact=?, image_path=? 
                    WHERE id=? AND seller_id=?''', 
                   (title, description, price, contact_info, image_path, item_id, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': '商品信息更新成功'})
    else:
        conn.close()
        return render_template('edit_item.html', item=item)

# 修改商品状态
@app.route('/update_item_status/<int:item_id>', methods=['POST'])
def update_item_status(item_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    new_status = request.form.get('status')
    if new_status not in ['available', 'sold', 'unavailable']:
        return jsonify({'status': 'error', 'message': '无效的状态值'}), 400
        
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 检查商品是否存在且属于当前用户
    c.execute("SELECT status FROM items WHERE id = ? AND seller_id = ?", (item_id, session['user_id']))
    item = c.fetchone()
    
    if not item:
        conn.close()
        return jsonify({'status': 'error', 'message': '商品不存在或您无权修改'}), 404
        
    # 检查商品是否处于交易中
    if item[0] == 'pending':
        conn.close()
        return jsonify({'status': 'error', 'message': '商品处于交易中，无法修改状态'}), 400
    
    # 更新商品状态
    c.execute("UPDATE items SET status = ? WHERE id = ? AND seller_id = ?", 
             (new_status, item_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': '商品状态已更新'})

# 批量管理商品
@app.route('/manage_items', methods=['GET', 'POST'])
def manage_items():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        item_ids = request.form.getlist('item_ids')
        
        if not item_ids:
            conn.close()
            return jsonify({'status': 'error', 'message': '未选择任何商品'}), 400
            
        if action not in ['available', 'unavailable', 'sold', 'delete']:
            conn.close()
            return jsonify({'status': 'error', 'message': '无效的操作'}), 400
        
        # 验证所有选中的商品是否属于当前用户且不在交易中
        placeholders = ','.join(['?'] * len(item_ids))
        params = item_ids + [session['user_id']]
        c.execute(f"SELECT id, status FROM items WHERE id IN ({placeholders}) AND seller_id = ?", params)
        items = c.fetchall()
        
        if len(items) != len(item_ids):
            conn.close()
            return jsonify({'status': 'error', 'message': '部分商品不存在或无权操作'}), 403
        
        # 检查是否有处于交易中的商品
        for item in items:
            if item['status'] == 'pending':
                conn.close()
                return jsonify({'status': 'error', 'message': '选中的商品中有处于交易中的商品，无法操作'}), 400
        
        # 执行批量操作
        if action == 'delete':
            # 删除商品
            c.execute(f"DELETE FROM items WHERE id IN ({placeholders}) AND seller_id = ?", params)
            message = '已成功删除选中的商品'
        else:
            # 更新状态
            status_params = [action] + params
            c.execute(f"UPDATE items SET status = ? WHERE id IN ({placeholders}) AND seller_id = ?", status_params)
            
            status_text = '上架' if action == 'available' else '下架' if action == 'unavailable' else '标记为已售出'
            message = f'已成功将选中的商品{status_text}'
            
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': message})
    else:
        # 获取用户的所有商品
        c.execute("""
            SELECT * FROM items 
            WHERE seller_id = ? 
            ORDER BY 
                CASE status
                    WHEN 'available' THEN 1
                    WHEN 'unavailable' THEN 2
                    WHEN 'pending' THEN 3
                    WHEN 'sold' THEN 4
                    ELSE 5
                END,
                created_at DESC
        """, (session['user_id'],))
        items = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return render_template('manage_items.html', items=items)

@app.route('/debug_image_paths')
def debug_image_paths():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT id, title, image_path FROM items")
    items = c.fetchall()
    result = ""
    for item in items:
        result += f"ID: {item[0]}, Title: {item[1]}, Image path: {item[2]}<br>"
    conn.close()
    return result

@app.route('/fix_image_paths')
def fix_image_paths():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 获取所有图片路径
    c.execute("SELECT id, image_path FROM items WHERE image_path IS NOT NULL")
    items = c.fetchall()
    
    updates = 0
    for item_id, image_path in items:
        if image_path and image_path.startswith('static/'):
            # 移除static/前缀
            new_path = image_path.replace('static/', '', 1)
            c.execute("UPDATE items SET image_path = ? WHERE id = ?", (new_path, item_id))
            updates += 1
    
    conn.commit()
    conn.close()
    return f"已修复 {updates} 条图片路径记录"

# 聊天功能路由

# 我的消息列表
@app.route('/messages')
def my_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # 获取与当前用户相关的所有对话
    c.execute("""
        SELECT 
            CASE 
                WHEN sender_id = ? THEN receiver_id 
                ELSE sender_id 
            END as contact_id,
            MAX(created_at) as last_message_time
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY contact_id
        ORDER BY last_message_time DESC
    """, (session['user_id'], session['user_id'], session['user_id']))
    
    contacts = []
    for row in c.fetchall():
        contact_id = row['contact_id']
        
        # 获取联系人信息
        c.execute("SELECT username FROM users WHERE id = ?", (contact_id,))
        contact_user = c.fetchone()
        
        if contact_user:
            # 获取最新的一条消息
            c.execute("""
                SELECT * FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                ORDER BY created_at DESC LIMIT 1
            """, (session['user_id'], contact_id, contact_id, session['user_id']))
            last_message = c.fetchone()
            
            # 获取未读消息数量
            c.execute("""
                SELECT COUNT(*) as unread_count FROM messages 
                WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
            """, (contact_id, session['user_id']))
            unread = c.fetchone()['unread_count']
            
            # 获取该联系人相关的最近一条消息的商品信息
            item_info = None
            if last_message and last_message['item_id']:
                c.execute("SELECT id, title, image_path FROM items WHERE id = ?", (last_message['item_id'],))
                item_row = c.fetchone()
                if item_row:
                    item_info = dict(item_row)
            
            contacts.append({
                'id': contact_id,
                'username': contact_user['username'],
                'last_message': dict(last_message) if last_message else None,
                'unread_count': unread,
                'item_info': item_info
            })
    
    conn.close()
    
    return render_template('messages.html', contacts=contacts)

# 与特定用户的对话
@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查聊天对象是否存在
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    chat_user = c.fetchone()
    
    if not chat_user:
        conn.close()
        return render_template('error.html', message='用户不存在')
    
    # 发送消息
    if request.method == 'POST':
        content = request.form.get('message')
        item_id = request.form.get('item_id')
        
        if content and content.strip():
            c.execute("""
                INSERT INTO messages (sender_id, receiver_id, item_id, content, created_at) 
                VALUES (?, ?, ?, ?, ?)
            """, (session['user_id'], user_id, item_id, content, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        
        # 如果是通过AJAX请求发送的消息，返回JSON响应
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success'})
        
        # 否则重定向回聊天页面
        return redirect(url_for('chat', user_id=user_id))
    
    # 获取对话历史
    c.execute("""
        SELECT m.*, u.username as sender_name 
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    
    messages = [dict(row) for row in c.fetchall()]
    
    # 标记该用户发给当前用户的所有消息为已读
    c.execute("""
        UPDATE messages SET is_read = 1
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
    """, (user_id, session['user_id']))
    conn.commit()
    
    # 获取相关商品信息
    items = {}
    for msg in messages:
        if msg['item_id'] and msg['item_id'] not in items:
            c.execute("SELECT id, title, price, image_path FROM items WHERE id = ?", (msg['item_id'],))
            item = c.fetchone()
            if item:
                items[msg['item_id']] = dict(item)
    
    # 获取当前用户卖的商品（用于快速选择）
    c.execute("""
        SELECT id, title FROM items 
        WHERE seller_id = ? AND status = 'available'
        ORDER BY created_at DESC
    """, (session['user_id'],))
    my_items = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return render_template('chat.html', 
                          chat_user=dict(chat_user), 
                          messages=messages, 
                          items=items,
                          my_items=my_items)

# 从商品页面发起聊天
@app.route('/contact_seller/<int:item_id>')
def contact_seller(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # 获取商品信息和卖家ID
    c.execute("SELECT seller_id FROM items WHERE id = ?", (item_id,))
    item = c.fetchone()
    
    if not item:
        conn.close()
        return render_template('error.html', message='商品不存在')
    
    seller_id = item[0]
    
    # 不能联系自己
    if seller_id == session['user_id']:
        conn.close()
        return render_template('error.html', message='不能与自己聊天')
    
    conn.close()
    
    # 重定向到与卖家的聊天页面，带上商品ID参数
    return redirect(url_for('chat', user_id=seller_id, item_id=item_id))

# 获取未读消息数
@app.route('/api/unread_message_count')
def unread_message_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("""
        SELECT COUNT(*) as count FROM messages 
        WHERE receiver_id = ? AND is_read = 0
    """, (session['user_id'],))
    
    result = c.fetchone()
    count = result[0] if result else 0
    
    conn.close()
    
    return jsonify({'count': count})

@app.before_request
def before_request():
    # 如果用户已登录，刷新会话
    if 'user_id' in session:
        session.permanent = True  # 确保会话是永久的
        session.modified = True   # 标记会话已被修改，强制更新
        app.logger.info(f"Session refreshed for user_id: {session['user_id']}")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
