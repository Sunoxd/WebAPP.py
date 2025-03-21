from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
from functools import wraps

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Mdet0805!.'
app.config['MYSQL_DB'] = 'flask_auth'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL
mysql = MySQL(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, inicie sesión para acceder a esta página', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Form validation
        error = None
        
        # Create cursor
        cur = mysql.connection.cursor()
        
        # Check if username exists
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cur.fetchone()
        if user:
            error = 'El usuario ya existe'
        
        # Check if email exists
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        if user:
            error = 'El correo electrónico ya existe'
        
        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            error = 'Formato de correo inválido'
        
        # Check password length
        if len(password) < 8:
            error = 'La contraseña debe tener al menos 8 caracteres'
        
        # Check if passwords match
        if password != confirm_password:
            error = 'Contraseña no encontrada'
        
        if error is None:
            # Hash password
            hashed_password = generate_password_hash(password)
            
            # Execute query
            cur.execute("INSERT INTO users(username, email, password) VALUES(%s, %s, %s)", 
                       (username, email, hashed_password))
            
            # Commit to DB
            mysql.connection.commit()
            
            # Close connection
            cur.close()
            
            flash('Registro exitoso, puedes ingresar ahora', 'success')
            return redirect(url_for('login'))
        
        # Close connection
        cur.close()
        flash(error, 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password_candidate = request.form['password']
        
        # Create cursor
        cur = mysql.connection.cursor()
        
        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        
        if result > 0:
            # Get stored hash
            user = cur.fetchone()
            password = user['password']
            
            # Compare passwords
            if check_password_hash(password, password_candidate):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                
                flash('Ya has iniciado sesión', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Inválido login'
                flash(error, 'danger')
                return render_template('login.html')
        else:
            error = 'Usuario no encontrado'
            flash(error, 'danger')
            return render_template('login.html')
        
        # Close connection
        cur.close()
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Ya has cerrado sesión', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)