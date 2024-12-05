from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import mysql.connector
from mysql.connector import Error
import re
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler

log_file = 'app.log'  # Log file name
log_handler = RotatingFileHandler(log_file, maxBytes=10000000, backupCount=3)  # File size limit 10MB
log_handler.setLevel(logging.INFO)  # You can use logging.DEBUG, logging.INFO, logging.ERROR, etc.

# Set the log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)

app = Flask(__name__)

# Add the handler to the Flask app logger
app.logger.addHandler(log_handler)

# You can also log SQL queries, etc.
app.logger.setLevel(logging.INFO)

# Configure the session lifetime (for example, 30 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Secret key for session management (ensure it's a strong, secure key)
app.secret_key = 'very_very_secure_key'  

# Session security configurations
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Prevent CSRF

# Setup Flask-Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not logged in

# Setup Flask-Limiter for rate limiting
limiter = Limiter(get_remote_address, app=app)

# Database connection configuration
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Use your MySQL username
        password="root",  # Use your MySQL password
        database="networkFinal"  # Use your database name
    )

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, full_name, role_type):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.role_type = role_type

    def __repr__(self):
        return f"<User {self.username}>"

# Load user by ID function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role_type FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()

    if user_data:
        user_id, username, full_name, role_type = user_data
        return User(user_id, username, full_name, role_type)
    return None

# Validation functions
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username) is not None

def is_valid_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[@$!%*?&]).{8,}$', password))

def is_valid_full_name(full_name):
    return re.match(r'^[a-zA-Z\s]{3,50}$', full_name) is not None

def is_valid_email(email):
    # Simple email validation regex
    return bool(re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email))


# Rate limiting decorator for the registration and login routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    app.logger.info('Register page accessed')
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        password_confirmation = request.form['password_confirmation']

        # Validate inputs
        if not is_valid_username(username):
            flash('Username must be between 3 and 20 characters, and can only contain letters, numbers, and underscores.', 'danger')
            return redirect(url_for('register'))

        if not is_valid_password(password):
            flash('Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.', 'danger')
            return redirect(url_for('register'))

        if not is_valid_full_name(full_name):
            flash('Full name must be between 3 and 50 characters and can only contain alphabetic characters and spaces.', 'danger')
            return redirect(url_for('register'))

        if not is_valid_email(email):
            flash('Invalid email address format. Please enter a valid email.', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != password_confirmation:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            # Establish a database connection
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Username or Email already exists. Please choose a different one.', 'danger')
                return redirect(url_for('register'))

            # Insert the new user into the database
            cursor.execute(
                "INSERT INTO users (username, full_name, email, password_hash) VALUES (%s, %s, %s, %s)",
                (username, full_name, email, password_hash)
            )

            conn.commit()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))  # Redirect to login page after registration

        except Error as e:
            print(f"Error: {e}")
            flash('Something went wrong. Please try again.', 'danger')
            return redirect(url_for('register'))

        finally:
            # Ensure that cursor and connection are closed properly
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('register.html')

# Login route with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit to 5 requests per minute
def login():
    app.logger.info('Login page accessed')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_valid_username(username):
            flash('Username must be between 3 and 20 characters, and can only contain letters, numbers, and underscores.', 'danger')
            return redirect(url_for('login'))

        # Retrieve the user from the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Modify the query to select the necessary columns
        cursor.execute("SELECT id, username, full_name, password_hash, role_type FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()

        cursor.close()
        conn.close()

        if user_data:
            # Unpack the results based on the columns from your schema
            user_id, stored_username, stored_full_name, stored_password_hash, stored_role_type = user_data

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):

                # Create the user object for Flask-Login
                user = User(user_id, stored_username, stored_full_name, stored_role_type)

                # Regenerate the session ID to prevent session fixation
                session.clear()  # Clear any old session data
                login_user(user)

                # Make the session permanent
                session.permanent = True

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Redirect to home page after successful login
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Username not found. Please try again.', 'danger')

    return render_template('login.html')

# Error handler for rate limiting
@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify(
        error="Too Many Requests",
        message="You have exceeded the allowed number of login attempts. Please try again after 1 minute."
    ), 429

# Main route (Home Page) - only accessible to logged-in users
@app.route('/')
def main():
    app.logger.info('Application started!')
    return render_template('index.html')

# Dashboard route - only accessible to logged-in users
@app.route('/dashboard')
@login_required
def dashboard():
    app.logger.info('Dashboard page accessed')
    if current_user.role_type == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html')

# Admin Dashboard route - only accessible to admins
@app.route('/admin')
@login_required
def admin_dashboard():
    app.logger.info('Admin page accessed')
    if current_user.role_type != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch all users from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, email, role_type FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    # Render the admin dashboard with the users data
    return render_template('admin.html', users=users)

# Create a new user - only accessible to admins
# Create a new user - only accessible to admins
@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if current_user.role_type != 'admin':
        flash('You do not have permission to create new users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get form data
    username = request.form['username']
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']
    # password_confirmation = request.form['password_confirmation']

    # Validate inputs
    if not is_valid_username(username):
        flash('Username must be between 3 and 20 characters, and can only contain letters, numbers, and underscores.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not is_valid_password(password):
        flash('Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not is_valid_full_name(full_name):
        flash('Full name must be between 3 and 50 characters and can only contain alphabetic characters and spaces.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not is_valid_email(email):
        flash('Invalid email address format. Please enter a valid email.', 'danger')
        return redirect(url_for('admin_dashboard'))


    # Hash the password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username or Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Insert the new user into the database with 'user' role
        cursor.execute(
            "INSERT INTO users (username, full_name, email, password_hash, role_type) VALUES (%s, %s, %s, %s, 'user')",
            (username, full_name, email, password_hash)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash('New user created successfully!', 'success')
        app.logger.info('New user is created')

    except Error as e:
        flash(f'Error creating user: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))


# Edit user - only accessible to admins
# Edit user - only accessible to admins
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role_type != 'admin':
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Fetch the user from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Handle form submission for updating user
        full_name = request.form['full_name']
        email = request.form['email']

        if not is_valid_full_name(full_name):
            flash('Full name must be between 3 and 50 characters and can only contain alphabetic characters and spaces.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        if not is_valid_email(email):
            flash('Invalid email address format. Please enter a valid email.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET full_name = %s, email = %s WHERE id = %s",
                (full_name, email, user_id)
            )
            conn.commit()
            cursor.close()
            conn.close()

            flash('User updated successfully!', 'success')
            app.logger.info('User information has been updated')
            return redirect(url_for('admin_dashboard'))
        except Error as e:
            flash(f'Error updating user: {e}', 'danger')

    return render_template('edit_user.html', user=user)

# Delete user - only accessible to admins
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role_type != 'admin':
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()

        flash('User deleted successfully!', 'success')
        app.logger.info('User is deleted')
    except Error as e:
        flash(f'Error deleting user: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Explicitly clear session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Add the HSTS Header to enforce HTTPS
@app.after_request
def set_hsts(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    app.run(debug=True)
