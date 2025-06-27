from flask import Flask, render_template, request, redirect, session, url_for
import mysql.connector
import bcrypt
from flask_assets import Environment, Bundle
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Initialize Flask-Assets
assets = Environment(app)

# Define the SCSS Bundle
scss = Bundle(
    'scss/styles.scss',
    filters='libsass',
    output='css/styles.css'
)

# Register the Bundle
assets.register('scss_all', scss)

# Build SCSS on startup
scss.build()

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'emm@N2020',
    'database': 'db_logindemo'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash.decode('utf-8'))
            )
            conn.commit()
            return redirect('/login')
        except mysql.connector.Error as err:
            error = f"Error: {err}"
        finally:
            cursor.close()
            conn.close()
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'attempts' not in session:
        session['attempts'] = 0

    error = None

    if request.method == 'POST':
        if session['attempts'] >= 3:
            error = 'Maximum login attempts reached.'
        else:
            username = request.form['username']
            password = request.form['password']

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['username'] = username
                session['attempts'] = 0
                return redirect('/dashboard')
            else:
                session['attempts'] += 1
                if session['attempts'] >= 3:
                    error = 'Maximum login attempts reached.'
                else:
                    error = 'Invalid username or password.'

    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route("/")
def home():
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)
