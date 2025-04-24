import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
import bcrypt
import time
from markupsafe import escape
import re
import html

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
                role TEXT DEFAULT 'user',
                is_suspended INTEGER DEFAULT 0,
                report_count INTEGER DEFAULT 0
            )
        """)

        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                report_count INTEGER DEFAULT 0 
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

        # 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 채팅 상대 목록 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_list (
                user_id TEXT NOT NULL,
                contact_id TEXT NOT NULL,
                UNIQUE(user_id, contact_id)
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
        username = html.escape(request.form['username'].strip())
        raw_password = request.form['password'].strip()

        # 사용자명 유효성 검사: 4~20자, 영문/숫자/밑줄(_)
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash('사용자명은 4~20자이며, 영문/숫자/밑줄(_)만 허용됩니다.')
            return redirect(url_for('register'))

        # 비밀번호 유효성 검사: 6~32자
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|-]{6,32}$', raw_password):
            flash('비밀번호는 6~32자이며, 영문/숫자/특수문자 조합만 허용됩니다.')
            return redirect(url_for('register'))

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
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    search_results = []
    if request.method == 'POST' and 'search_query' in request.form:
        search_query = escape(request.form['search_query']).strip()

        # 서버 측 검색어 길이 검증
        if len(search_query) == 0:
            flash('검색어를 입력해주세요.')
            return redirect(url_for('dashboard'))
        if len(search_query) > 30:
            flash('검색어는 최대 30자까지 입력 가능합니다.')
            return redirect(url_for('dashboard'))

        # 검색 수행
        search_query = f"%{search_query}%"
        cursor.execute(
            "SELECT * FROM product WHERE title LIKE ? OR description LIKE ?",
            (search_query, search_query)
        )
        search_results = cursor.fetchall()

    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()

    return render_template(
        'dashboard.html',
        user=current_user,
        products=all_products,
        search_results=search_results
    )

# 프로필 페이지
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

    # 관리자 계정인지 확인
    if current_user['role'] == 'admin':
        # 관리자: 모든 상품 조회
        cursor.execute("SELECT * FROM product")
        user_products = cursor.fetchall()
    else:
        # 일반 사용자: 본인이 등록한 상품만 조회
        cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
        user_products = cursor.fetchall()

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
        
        elif 'delete_product_id' in request.form:
            product_id = request.form['delete_product_id']

            # 관리자 계정인지 확인
            if current_user['role'] == 'admin':
                # 관리자: 모든 상품 삭제 가능
                cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
                db.commit()
                flash('상품이 삭제되었습니다.')
            else:
                # 일반 사용자: 본인이 등록한 상품만 삭제 가능
                cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
                product = cursor.fetchone()
                if product:
                    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
                    db.commit()
                    flash('상품이 삭제되었습니다.')
                else:
                    flash('삭제 권한이 없습니다.')
            return redirect(url_for('profile'))

        elif 'current_password' in request.form and 'new_password' in request.form:
            # 비밀번호 변경 처리
            current_password = request.form['current_password'].strip()
            new_password = request.form['new_password'].strip()

            # 현재 비밀번호 확인
            if not bcrypt.checkpw(current_password.encode('utf-8'), current_user['password']):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))

            # 새 비밀번호 유효성 검사
            if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|-]{6,32}$', new_password):
                flash('새 비밀번호는 6~32자이며, 영문/숫자/특수문자 조합만 허용됩니다.')
                return redirect(url_for('profile'))

            # 새 비밀번호 해싱 및 저장
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new_password, session['user_id']))
            db.commit()
            flash('비밀번호가 성공적으로 변경되었습니다.')
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

        elif 'suspend_user_id' in request.form:
            # 관리자: 사용자 휴면 계정 설정/해제
            suspend_user_id = request.form.get('suspend_user_id')
            cursor.execute("SELECT is_suspended FROM user WHERE id = ?", (suspend_user_id,))
            user = cursor.fetchone()
            if user:
                new_status = 0 if user['is_suspended'] else 1
                cursor.execute("UPDATE user SET is_suspended = ? WHERE id = ?", (new_status, suspend_user_id))
                db.commit()
                if new_status == 1:
                    flash('사용자가 휴면 계정으로 설정되었습니다.')
                else:
                    flash('사용자의 휴면 계정이 해제되었습니다.')
            else:
                flash('사용자를 찾을 수 없습니다.')

    return render_template(
        'profile.html',
        user=current_user,
        searched_user=searched_user,
        searched_products=searched_products,
        user_products=user_products
    )


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보 확인
    cursor.execute("SELECT is_suspended FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if user['is_suspended']:
        flash('휴면 계정 상태에서는 상품을 등록할 수 없습니다.')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        title = escape(request.form['title']).strip()
        description = escape(request.form['description']).strip()
        price = escape(request.form['price']).strip()

        # 제목과 설명 길이 제한
        if len(title) > 30:
            flash('제목은 최대 30자까지 입력 가능합니다.')
            return redirect(url_for('new_product'))
        if len(description) > 200:
            flash('설명은 최대 200자까지 입력 가능합니다.')
            return redirect(url_for('new_product'))

        if not title or not description or not re.match(r'^\d+(\.\d{1,2})?$', price):
            flash('유효하지 않은 상품 정보입니다.')
            return redirect(url_for('new_product'))

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
@app.route('/product/<product_id>', methods=['GET', 'POST'])
def view_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    # 본인의 상품인지 확인
    is_owner = session['user_id'] == product['seller_id']

    if request.method == 'POST' and is_owner:
        # 상품 수정 처리
        title = escape(request.form['title']).strip()
        description = escape(request.form['description']).strip()
        price = escape(request.form['price']).strip()

        # 제목과 설명 길이 제한
        if len(title) > 30:
            flash('제목은 최대 30자까지 입력 가능합니다.')
            return redirect(url_for('view_product', product_id=product_id))
        if len(description) > 200:
            flash('설명은 최대 200자까지 입력 가능합니다.')
            return redirect(url_for('view_product', product_id=product_id))

        if not title or not description or not re.match(r'^\d+(\.\d{1,2})?$', price):
            flash('유효하지 않은 상품 정보입니다.')
            return redirect(url_for('view_product', product_id=product_id))

        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, price, product_id)
        )
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('view_product.html', product=product, seller=seller, is_owner=is_owner)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        report_type = request.form.get('report_type')  # 'product' 또는 'user'
        reason = escape(request.form['reason']).strip()

        if report_type == 'product':
            target_title = escape(request.form['target_title']).strip()

            if not target_title or not reason:
                flash('상품 제목과 신고 사유를 모두 입력해주세요.')
                return redirect(url_for('report'))

            # 상품 신고 처리 로직 (기존 코드 유지)
            cursor.execute("SELECT id, report_count FROM product WHERE title = ?", (target_title,))
            product = cursor.fetchone()

            if not product:
                flash('해당 제목의 상품을 찾을 수 없습니다.')
                return redirect(url_for('report'))

            target_id = product['id']
            report_count = product['report_count']

            # 동일 사용자의 중복 신고 여부 확인
            cursor.execute(
                "SELECT * FROM report WHERE reporter_id = ? AND target_id = ?",
                (session['user_id'], target_id)
            )
            existing_report = cursor.fetchone()

            if existing_report:
                flash('이미 해당 상품을 신고하셨습니다.')
                return redirect(url_for('report'))

            # 신고 데이터 삽입
            report_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                (report_id, session['user_id'], target_id, reason)
            )

            # 신고당한 상품의 report_count 증가
            cursor.execute(
                "UPDATE product SET report_count = report_count + 1 WHERE id = ?",
                (target_id,)
            )

            # 신고 횟수가 3회를 초과하면 상품 삭제
            if report_count + 1 > 3:
                cursor.execute("DELETE FROM product WHERE id = ?", (target_id,))
                db.commit()
                flash('상품이 신고 횟수 초과로 삭제되었습니다.')
            else:
                db.commit()
                flash('신고가 접수되었습니다.')

        elif report_type == 'user':
            target_username = escape(request.form['target_username']).strip()

            if not target_username or not reason:
                flash('사용자명과 신고 사유를 모두 입력해주세요.')
                return redirect(url_for('report'))

            # 사용자 신고 처리 로직
            cursor.execute("SELECT id, role, is_suspended, report_count FROM user WHERE username = ?", (target_username,))
            user = cursor.fetchone()

            if not user:
                flash('해당 사용자를 찾을 수 없습니다.')
                return redirect(url_for('report'))

            # 관리자인 경우 신고 차단
            if user['role'] == 'admin':
                flash('관리자는 신고할 수 없습니다.')
                return redirect(url_for('report'))

            target_id = user['id']
            is_suspended = user['is_suspended']
            report_count = user['report_count']

            # 동일 사용자의 중복 신고 여부 확인
            cursor.execute(
                "SELECT * FROM report WHERE reporter_id = ? AND target_id = ?",
                (session['user_id'], target_id)
            )
            existing_report = cursor.fetchone()

            if existing_report:
                flash('이미 해당 사용자를 신고하셨습니다.')
                return redirect(url_for('report'))

            # 신고 데이터 삽입
            report_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                (report_id, session['user_id'], target_id, reason)
            )

            # 신고당한 유저의 신고 횟수 증가
            cursor.execute(
                "UPDATE user SET report_count = report_count + 1 WHERE id = ?",
                (target_id,)
            )

            # 신고 횟수가 3회를 초과하면 계정을 휴면 상태로 전환
            if report_count + 1 > 3 and not is_suspended:
                cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ?", (target_id,))
                db.commit()
                flash('해당 사용자가 신고 횟수 초과로 휴면 계정이 되었습니다.')
            else:
                db.commit()
                flash('신고가 접수되었습니다.')

        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message_all')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    message = data['message']

    # 데이터베이스에 메시지 저장
    db = get_db()
    cursor = db.cursor()
    chat_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat (id, sender_id, receiver_id, message) 
        VALUES (?, ?, ?, ?)
    """, (chat_id, sender_id, receiver_id, message))
    db.commit()

    # 상대방의 이름 가져오기
    cursor.execute("SELECT username FROM user WHERE id = ?", (receiver_id,))
    receiver_username = cursor.fetchone()['username']

    # 메시지를 수신자와 발신자에게 전송
    emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'message': message,
        'sender_username': data['sender_username'],
        'receiver_username': receiver_username
    }, room=receiver_id)
    emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'message': message,
        'sender_username': data['sender_username'],
        'receiver_username': receiver_username
    }, room=sender_id)

# WebSocket 이벤트: 채팅방 참여
@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

    # 이전 대화 기록 로드
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT sender_id, receiver_id, message, timestamp
        FROM chat
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], room, room, session['user_id']))
    chat_history = cursor.fetchall()

    # 상대방의 이름 가져오기
    cursor.execute("SELECT username FROM user WHERE id = ?", (room,))
    receiver_username = cursor.fetchone()['username']

    # 대화 기록을 클라이언트로 전송
    emit('load_chat_history', {
        'chat_history': [
            {
                'sender_id': row['sender_id'],
                'receiver_id': row['receiver_id'],
                'message': row['message'],
                'timestamp': row['timestamp'],
                'receiver_username': receiver_username
            }
            for row in chat_history
        ]
    }, room=request.sid)

    # emit('status', {'msg': f"{session['user_id']}님이 방에 입장했습니다."}, room=room)

# WebSocket 이벤트: 채팅방 나가기
@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    # emit('status', {'msg': f"{session['user_id']}님이 방에서 나갔습니다."}, room=room)

# 채팅 페이지
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 채팅 상대 목록 조회
    cursor.execute("""
        SELECT u.id, u.username 
        FROM chat_list cl
        JOIN user u ON cl.contact_id = u.id
        WHERE cl.user_id = ?
    """, (session['user_id'],))
    chat_contacts = cursor.fetchall()

    selected_contact = None
    chat_messages = []

    if request.method == 'POST':
        if 'search_user' in request.form:
            # 사용자 검색
            search_username = escape(request.form['search_user']).strip()
            cursor.execute("SELECT * FROM user WHERE username = ?", (search_username,))
            selected_contact = cursor.fetchone()

            if not selected_contact:
                flash('해당 사용자를 찾을 수 없습니다.')
            elif selected_contact['id'] == session['user_id']:
                flash('자기 자신과는 채팅할 수 없습니다.')
            else:
                # 채팅 상대 목록에 추가
                cursor.execute("""
                    INSERT OR IGNORE INTO chat_list (user_id, contact_id) VALUES (?, ?)
                """, (session['user_id'], selected_contact['id']))
                cursor.execute("""
                    INSERT OR IGNORE INTO chat_list (user_id, contact_id) VALUES (?, ?)
                """, (selected_contact['id'], session['user_id']))
                db.commit()

        elif 'selected_contact_id' in request.form:
            # 채팅 상대 선택
            selected_contact_id = request.form['selected_contact_id']
            cursor.execute("SELECT * FROM user WHERE id = ?", (selected_contact_id,))
            selected_contact = cursor.fetchone()

            # 채팅 메시지 조회
            cursor.execute("""
                SELECT * FROM chat 
                WHERE (sender_id = ? AND receiver_id = ?)
                   OR (sender_id = ? AND receiver_id = ?)
                ORDER BY timestamp ASC
            """, (session['user_id'], selected_contact_id, selected_contact_id, session['user_id']))
            chat_messages = cursor.fetchall()

        elif 'message' in request.form:
            # 메시지 전송
            message = escape(request.form['message']).strip()
            receiver_id = request.form['receiver_id']

            if message:
                chat_id = str(uuid.uuid4())
                cursor.execute("""
                    INSERT INTO chat (id, sender_id, receiver_id, message) 
                    VALUES (?, ?, ?, ?)
                """, (chat_id, session['user_id'], receiver_id, message))
                db.commit()

                # 메시지 전송 후 채팅 메시지 갱신
                cursor.execute("""
                    SELECT * FROM chat 
                    WHERE (sender_id = ? AND receiver_id = ?)
                       OR (sender_id = ? AND receiver_id = ?)
                    ORDER BY timestamp ASC
                """, (session['user_id'], receiver_id, receiver_id, session['user_id']))
                chat_messages = cursor.fetchall()

    return render_template(
        'chat.html',
        user=current_user,
        chat_contacts=chat_contacts,
        selected_contact=selected_contact,
        chat_messages=chat_messages
    )

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def not_found(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
    #app.run(host='0.0.0.0', port=5001, debug=True)
