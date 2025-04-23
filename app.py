import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
import bcrypt
import time
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS에서만 작동하도록
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
DATABASE = 'market.db'

csrf = CSRFProtect(app)
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                role TEXT DEFAULT 'user'
            )
        """)

        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        cursor.execute("SELECT * FROM user WHERE username = ?", ("123",))
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            raw_password = "123"
            hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt())

            cursor.execute("""
                INSERT INTO user (id, username, password, role)
                VALUES (?, ?, ?, 'admin')
            """, (admin_id, "123", hashed_password))


        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']
        hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입 완료. 로그인해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

login_attempts = {}  # username: (count, last_attempt_timestamp)

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    global login_attempts
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        attempt = login_attempts.get(username, [0, 0])
        if attempt[0] >= 5 and time.time() - attempt[1] < 60:
            flash("잠시 후 다시 시도하세요.")
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            login_attempts.pop(username, None)  # 성공 시 초기화
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            login_attempts[username] = [attempt[0] + 1, time.time()]
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    searched_user = None
    searched_products = []

    if request.method == 'POST':
        if 'bio' in request.form:
            bio = escape(request.form.get('bio', '').strip())
            if len(bio) > 500:
                flash('자기소개는 500자 이하로 작성해주세요.')
            else:
                cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
                db.commit()
                flash('프로필이 업데이트되었습니다.')
            return redirect(url_for('profile'))

        elif 'search_username' in request.form:
            # 사용자 검색
            search_username = request.form.get('search_username')
            cursor.execute("SELECT * FROM user WHERE username = ?", (search_username,))
            searched_user = cursor.fetchone()

            if searched_user:
                # 해당 사용자가 등록한 상품 목록
                cursor.execute("SELECT * FROM product WHERE seller_id = ?", (searched_user['id'],))
                searched_products = cursor.fetchall()
            else:
                flash(f'"{search_username}" 사용자를 찾을 수 없습니다.')

        elif 'delete_user_id' in request.form:
            # 관리자만 사용자 삭제
            if current_user['role'] == 'admin':
                delete_user_id = request.form.get('delete_user_id')
                cursor.execute("DELETE FROM user WHERE id = ?", (delete_user_id,))
                cursor.execute("DELETE FROM product WHERE seller_id = ?", (delete_user_id,))
                db.commit()
                flash('사용자가 삭제되었습니다.')
            else:
                flash('권한이 없습니다.')

    return render_template(
        'profile.html',
        user=current_user,
        searched_user=searched_user,
        searched_products=searched_products
    )


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = escape(request.form['title']).strip()
        description = escape(request.form['description']).strip()
        price = escape(request.form['price']).strip()

        if not title or not description or not re.match(r'^\d+(\.\d{1,2})?$', price):
            flash('유효하지 않은 상품 정보입니다.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = escape(request.form['reason']).strip()

        if not reason:
            flash('신고 사유를 입력해주세요.')
            return redirect(url_for('report'))

        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
