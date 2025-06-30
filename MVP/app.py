from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key'
DB = 'database.db'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, is_admin FROM users WHERE id=?", (user_id,))
        user_data = cur.fetchone()
        if user_data:
            return User(*user_data)
    return None

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB)
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'активно',
                done BOOLEAN NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                time_spent INTEGER DEFAULT 0,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                task_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        cur = db.cursor()
        cur.execute("PRAGMA table_info(tasks)")
        columns = [column[1] for column in cur.fetchall()]
        if 'status' not in columns:
            db.execute('ALTER TABLE tasks ADD COLUMN status TEXT DEFAULT "активно"')

        try:
            admin_pass = generate_password_hash('admin', method='pbkdf2:sha256')
            db.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                      ('admin', admin_pass, 1))
            db.commit()
        except sqlite3.IntegrityError:
            pass

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with sqlite3.connect(DB) as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Пользователь уже существует"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DB) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password, is_admin FROM users WHERE username=?", (username,))
            user_data = cur.fetchone()
            if user_data and check_password_hash(user_data[2], password):
                user = User(user_data[0], user_data[1], user_data[3])
                login_user(user)
                return redirect(url_for('tasks'))
            else:
                return "Неверный логин или пароль"
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/tasks', defaults={'filter': 'all'})
@app.route('/tasks/<filter>')
@login_required
def tasks(filter):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        query = "SELECT id, content, done, created_at, time_spent, status FROM tasks WHERE user_id=?"

        if filter == 'ready':
            query += " AND status='Готово'"
        elif filter == 'canceled':
            query += " AND status='Отмена'"
        elif filter == 'reopened':
            query += " AND status='Переоткрыть'"
        elif filter == 'not_actual':
            query += " AND status='Неактуально'"

        cur.execute(query, (current_user.id,))
        tasks = cur.fetchall()
    return render_template('tasks.html', tasks=tasks, filter=filter)

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    content = request.form['content']
    description = request.form.get('description', '')
    if content.strip():
        with sqlite3.connect(DB) as conn:
            conn.execute("INSERT INTO tasks (content, description, user_id) VALUES (?, ?, ?)",
                         (content, description, current_user.id))
    return redirect(url_for('tasks'))

@app.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (task_id, current_user.id))
    return redirect(url_for('tasks'))

@app.route('/toggle/<int:task_id>')
@login_required
def toggle(task_id):
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT done FROM tasks WHERE id=? AND user_id=?", (task_id, current_user.id))
        result = cursor.fetchone()
        if result:
            done = result[0]
            conn.execute("UPDATE tasks SET done = ? WHERE id = ?", (not done, task_id))
    return redirect(url_for('tasks'))

@app.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, content, description, done, created_at, time_spent, status 
            FROM tasks WHERE id = ? AND user_id = ?
        """, (task_id, current_user.id))
        task = cur.fetchone()

        if not task:
            return "Задача не найдена", 404

        cur.execute("""
            SELECT c.text, c.created_at, u.username
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.task_id = ?
            ORDER BY c.created_at DESC
        """, (task_id,))
        comments = cur.fetchall()

    return render_template('task_detail.html', task=task, comments=comments)

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    if request.method == 'POST':
        content = request.form['content']
        description = request.form['description']
        time_spent = int(request.form['time_spent']) * 60
        with sqlite3.connect(DB) as conn:
            conn.execute("""
                UPDATE tasks 
                SET content = ?, description = ?, time_spent = ?
                WHERE id = ? AND user_id = ?
            """, (content, description, time_spent, task_id, current_user.id))
        return redirect(url_for('tasks'))

    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, content, description, time_spent FROM tasks WHERE id = ? AND user_id = ?",
                    (task_id, current_user.id))
        task = cur.fetchone()
        if not task:
            return "Задача не найдена", 404
    return render_template('edit_task.html', task=task)

@app.route('/add_comment/<int:task_id>', methods=['POST'])
@login_required
def add_comment(task_id):
    comment_text = request.form['comment']
    if comment_text.strip():
        with sqlite3.connect(DB) as conn:
            conn.execute("""
                INSERT INTO comments (task_id, user_id, text)
                VALUES (?, ?, ?)
            """, (task_id, current_user.id, comment_text))
    return redirect(url_for('task_detail', task_id=task_id))

@app.route('/update_status/<int:task_id>', methods=['POST'])
@login_required
def update_status(task_id):
    new_status = request.form.get('status')
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?",
                    (new_status, task_id, current_user.id))
    return redirect(url_for('task_detail', task_id=task_id))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        content = request.form['content']
        description = request.form.get('description', '')
        if content.strip():
            with sqlite3.connect(DB) as conn:
                conn.execute("INSERT INTO tasks (content, description, user_id) VALUES (?, ?, ?)",
                             (content, description, current_user.id))
        return redirect(url_for('tasks'))
    return render_template('create.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "Доступ запрещен", 403
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, is_admin FROM users")
        users = cur.fetchall()
        cur.execute("SELECT t.id, t.content, u.username, t.time_spent FROM tasks t JOIN users u ON t.user_id = u.id")
        tasks = cur.fetchall()
    return render_template('admin.html', users=users, tasks=tasks)

@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, content, description, status, done, time_spent, created_at FROM tasks WHERE user_id=?", (current_user.id,))
        tasks = cur.fetchall()

    result = [
        {
            'id': t[0],
            'content': t[1],
            'description': t[2],
            'status': t[3].capitalize(),
            'done': bool(t[4]),
            'time_spent': t[5],
            'created_at': t[6]
        }
        for t in tasks
    ]
    return jsonify(result)

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task_api():
    data = request.get_json()
    content = data.get('content')
    description = data.get('description', '')
    status = data.get('status', 'активно').lower()

    if not content:
        return jsonify({'error': 'Текст задачи обязателен'}), 400

    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO tasks (content, description, status, user_id)
            VALUES (?, ?, ?, ?)
        """, (content, description, status, current_user.id))
        task_id = cur.lastrowid
        conn.commit()

    return jsonify({
        'id': task_id,
        'message': 'Задача создана'
    }), 201

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_task_api(task_id):
    data = request.get_json()
    content = data.get('content')
    description = data.get('description')
    status = data.get('status')
    done = data.get('done')
    time_spent = data.get('time_spent')

    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM tasks WHERE id=? AND user_id=?", (task_id, current_user.id))
        if not cur.fetchone():
            return jsonify({'error': 'Задача не найдена или доступ запрещён'}), 404

        update_fields = []
        values = []

        if content is not None:
            update_fields.append("content = ?")
            values.append(content)

        if description is not None:
            update_fields.append("description = ?")
            values.append(description)

        if status is not None:
            update_fields.append("status = ?")
            values.append(status.lower())

        if done is not None:
            update_fields.append("done = ?")
            values.append(1 if done else 0)

        if time_spent is not None:
            update_fields.append("time_spent = ?")
            values.append(time_spent)

        if update_fields:
            query = f"UPDATE tasks SET {', '.join(update_fields)} WHERE id = ?"
            values.append(task_id)
            cur.execute(query, tuple(values))
            conn.commit()

    return jsonify({'id': task_id, 'message': 'Задача обновлена'}), 200

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task_api(task_id):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, current_user.id))
        if cur.rowcount == 0:
            return jsonify({'error': 'Задача не найдена или доступ запрещён'}), 404

    return jsonify({'id': task_id, 'message': 'Задача удалена'}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)