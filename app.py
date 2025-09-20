# =============================================================================
# IMS (Information Management System) - Flask Application
# =============================================================================
# This application provides a comprehensive student information management system
# with role-based access control for Students, Requesters, Admins, and Third-Party users.
# 
# Features:
# - User authentication and authorization
# - Student profile management
# - Access request system with approval workflow
# - Admin dashboard and user management
# - Third-party API access
# - Comprehensive logging and audit trails
# =============================================================================

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from functools import wraps
import jwt
import pymysql
import hashlib
import secrets
import string
from datetime import datetime, timedelta

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'TMC'  # Use a secure random key in production!

# =============================================================================
# ERROR HANDLING SYSTEM
# =============================================================================

def handle_error(error_message, error_title="Error", status_code=400, is_api_request=False):
    """
    Centralized error handling function for consistent error responses across the application.
    
    Args:
        error_message (str): The error message to display to the user
        error_title (str): The title for the error alert (default: "Error")
        status_code (int): HTTP status code (default: 400)
        is_api_request (bool): Whether this is an API request (default: False)
    
    Returns:
        - For web requests: Redirect with flash message (displays Sweet Alert)
        - For API requests: JSON response with error details
    
    This function ensures that:
    - Web users see user-friendly Sweet Alert popups instead of JSON errors
    - API clients receive proper JSON error responses
    - Error handling is consistent across all routes
    """
    if is_api_request or request.is_json or request.path.startswith('/api/'):
        # API requests should receive JSON responses
        return jsonify({'error': error_message}), status_code
    else:
        # Web requests use flash messages that trigger Sweet Alert popups
        flash(error_message, 'error')
        return redirect(request.referrer or url_for('home'))

# =============================================================================
# API AUTHENTICATION SYSTEM
# =============================================================================

def generate_api_key():
    """
    Generate a cryptographically secure API key for third-party users.
    
    Returns:
        str: A 32-character random string containing letters and digits
    
    Security Features:
    - Uses Python's secrets module for cryptographically secure randomness
    - 32 characters provide 62^32 possible combinations
    - Suitable for API authentication tokens
    """
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

def verify_api_key(api_key):
    """
    Verify if an API key is valid and belongs to an active third-party user.
    
    Args:
        api_key (str): The API key to verify
    
    Returns:
        dict: User information if valid, None if invalid
    
    Database Query:
    - Checks if API key exists in users table
    - Ensures user has 'Third_Party' role
    - Returns user details for authenticated requests
    """
    conn = None
    cur = None
    try:
        # Establish database connection
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Query for valid third-party user with matching API key
        cur.execute("SELECT user_id, full_name, role FROM users WHERE api_key = %s AND role = 'Third_Party'", (api_key,))
        user = cur.fetchone()
        return user
    except Exception as e:
        print(f"Error verifying API key: {e}")
        return None
    finally:
        # Always close database connections
        if cur:
            cur.close()
        if conn:
            conn.close()

def require_api_key(f):
    """
    Decorator to require valid API key authentication for API endpoints.
    
    This decorator:
    1. Extracts API key from X-API-Key header
    2. Verifies the API key is valid and belongs to a third-party user
    3. Adds user information to request context for use in the decorated function
    4. Returns 401 error if authentication fails
    
    Usage:
        @app.route('/api/v1/endpoint')
        @require_api_key
        def protected_endpoint():
            # request.third_party_user contains authenticated user info
            pass
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract API key from request headers
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Verify API key and get user information
        user = verify_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Add authenticated user info to request context
        request.third_party_user = user
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# MAIN APPLICATION ROUTES
# =============================================================================

@app.route('/')
def home():
    """
    Home route - redirects to login page.
    
    Returns:
        Rendered login template for user authentication
    """
    return render_template('login/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration route - handles both GET and POST requests.
    
    GET: Displays registration form
    POST: Processes user registration with validation
    
    Registration Process:
    1. Validates required fields (name, email, password, role)
    2. Checks for duplicate email addresses
    3. Validates student ID uniqueness for student role
    4. Hashes password securely
    5. Creates user account in database
    6. Redirects to login page on success
    
    Security Features:
    - Password hashing using SHA-256
    - Input validation and sanitization
    - Duplicate email/student ID prevention
    - Role-based validation
    """
    if request.method == 'GET':
        # Display registration form
        return render_template('register/register.html')
    
    # Process registration form submission
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    print("Connected to the database")
    try:
        cur = conn.cursor()

        # Extract and sanitize form data
        full_name = request.form.get("full_name", '').strip()
        email = request.form.get("email", '').strip()
        student_id = request.form.get("student_id", '').strip()
        password = request.form.get("password", '')
        confirm_password = request.form.get("confirm_password", '')
        role = request.form.get("role", 'Student').strip()
        department = request.form.get("department", 'General').strip()
        contact_number = request.form.get("contact_number", '').strip()
        
        # Input validation - ensure all required fields are provided
        if not all([full_name, email, password, confirm_password, role]):
            return handle_error('All required fields must be filled', 'Validation Error', 400)
        
        # Password confirmation validation
        if password != confirm_password:
            return handle_error('Passwords do not match', 'Validation Error', 400)
        
        # Set default values for new user
        status = 1  # Active user status
        
        # Role-specific validation - students must have a student ID
        if role == 'Student' and not student_id:
            return handle_error('Student ID is required for student registration', 'Validation Error', 400)
        
        print(f"Received data: full_name={full_name}, email={email}, student_id={student_id}, role={role}")
        
        # Security: Hash password using SHA-256 before storing
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"Password hash: {password_hash}")
        
        # Database validation - check for duplicate email addresses
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        print(f"User found: {user}")
        if user:
            return handle_error('Email already registered', 'Registration Failed', 409)
        
        # Database validation - check for duplicate student IDs (students only)
        if role == 'Student' and student_id:
            cur.execute("SELECT * FROM users WHERE student_id = %s", (student_id,))
            existing_student = cur.fetchone()
            if existing_student:
                return handle_error('Student ID already registered', 'Registration Failed', 409)
        
        print("No existing user found, proceeding with registration")
        
        # Create new user account in database
        cur.execute("INSERT INTO users (email, password_hash, full_name, student_id, department, role, status, contact_no) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (email, password_hash, full_name, student_id, department, role, status, contact_number))
        conn.commit()
        print("User inserted successfully")
        # Get inserted user ID
        user_id = cur.lastrowid

        token = jwt.encode(
        {'id': int(user_id), 'role': str(role)},
        str(app.config['SECRET_KEY']),
        algorithm='HS256'
            )
       
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return redirect(url_for('login'))
        # return jsonify({'message': 'User registered successfully', 'token': token}), 201
    
    except Exception as e:
        print(f"Error: {e}")
        return handle_error('An error occurred during registration', 'Registration Error', 500)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password/forgot_password.html')
    
    try:
        email = request.form.get('email', '').strip()
        if not email:
            return handle_error('Email is required', 'Validation Error', 400)
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Check if email exists
        cur.execute("SELECT user_id, full_name FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        if not user:
            return handle_error('Email not found', 'User Not Found', 404)
        
        # In a real application, you would:
        # 1. Generate a secure reset token
        # 2. Store it in the database with expiration
        # 3. Send an email with the reset link
        # For now, we'll just return a success message
        
        print(f"Password reset requested for user: {user['full_name']} ({email})")
        
        return jsonify({'message': 'Password reset instructions have been sent to your email'}), 200
        
    except Exception as e:
        print(f"Error in forgot password: {e}")
        return handle_error('An error occurred while processing your request', 'Request Error', 500)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User authentication route - handles both GET and POST requests.
    
    GET: Displays login form
    POST: Processes user authentication
    
    Authentication Process:
    1. Validates email and password
    2. Hashes provided password for comparison
    3. Queries database for matching user
    4. Logs login attempts (successful and failed)
    5. Creates user session on successful authentication
    6. Redirects to appropriate dashboard based on user role
    
    Security Features:
    - Password hashing and secure comparison
    - Login attempt logging with IP tracking
    - Session management
    - Role-based redirection
    - JWT token generation for API access
    """
    if request.method == 'GET':
        # Display login form
        return render_template('login/login.html')
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        email = request.form.get("email")
        password = request.form.get("password")
        print(f"Login attempt with email: {email}")

        # Create login_attempts table if it doesn't exist
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                attempt_id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255),
                login_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                ip_address VARCHAR(45)
            )
        """)

        # Log the login attempt (initially as failed)
        cur.execute("""
            INSERT INTO login_attempts (email, success, ip_address)
            VALUES (%s, %s, %s)
        """, (email, False, request.remote_addr))

        # Hash the provided password to compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Look up user by email
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        print(f"User found: {user}")
        print(f"Provided password hash: {password_hash}")
        print(f"Stored password hash: {user['password_hash']}")
        if not user or user['password_hash'] != password_hash:
            conn.commit()  # Commit the failed attempt
            return handle_error('Invalid email or password', 'Login Failed', 401)
        print("User authenticated successfully")
        
        # Update the login attempt as successful
        cur.execute("""
    UPDATE login_attempts
    SET success = TRUE
    WHERE email = %s
    ORDER BY login_timestamp DESC
    LIMIT 1
""", (email,))
        
        session['user_id'] = user['user_id']
        session['role'] = user['role']
        print(f"Session set - user_id: {session['user_id']}, role: {session['role']}")
                
        # Create JWT token
        token = jwt.encode(
            {'id': int(user['user_id']), 'role': str(user['role'])},
            str(app.config['SECRET_KEY']),
            algorithm='HS256'
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        conn.commit()  # Commit the successful login attempt

        if user['role'] == 'Student':
            return redirect(url_for('students'))
        elif user['role'] == 'Admin':
            return redirect(url_for('admin_dashboard'))
        elif user['role'] == 'Requester':
            return redirect(url_for('requester'))
        elif user['role'] == 'Third_Party':
            return redirect(url_for('third_party_dashboard'))
        else:
            return handle_error('Unauthorized role', 'Access Denied', 403)

    except Exception as e:
        print(f"Login Error: {e}")
        return handle_error('An error occurred during login', 'Login Error', 500)

def jwt_required_custom(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Missing token'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            identity = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.identity = identity
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/profile', methods=['POST'])
def add_profile():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        print("Connected to the database for profile addition")
        cur = conn.cursor()
        # identity = request.identity
        # print(f"User identity: {identity}")
        data = request.get_json()
        print(f"Profile data: {data}")
        cur.execute(
            "INSERT INTO profiles (user_id, profile_type, data) VALUES (%s, %s, %s)",
            (1, data['profile_type'], data['data'])
        )
        conn.commit()

        return jsonify({'message': 'Profile added'}), 201
    except Exception as e:
        print(f"Error adding profile: {e}")
        return jsonify({'error': 'Error adding profile'}), 500

@app.route('/profile', methods=['GET'])
def get_profile():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        requester_role = request.args.get('role')
        requester_id = request.args.get('id')
        user_id = request.args.get('user_id')

        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        # Fetch allowed profile types   
        cur.execute("SELECT profile_type FROM access_rules WHERE user_id = %s AND role = %s", (user_id, requester_role))
        allowed = cur.fetchall()
        profile_types = [row['profile_type'] for row in allowed]
        print(f"Allowed profile types: {profile_types}")
        if not profile_types:
            return jsonify({'profiles': []}), 200

        # Fetch profiles
        format_strings = ','.join(['%s'] * len(profile_types))
        cur.execute(f"SELECT profile_type, data FROM profiles WHERE user_id = %s AND profile_type IN ({format_strings})", [user_id] + profile_types)
        profiles = cur.fetchall()
        print(f"Fetched profiles: {profiles}")
        # Log access to audit_logs (existing)
        cur.execute(
            "INSERT INTO audit_logs (user_id, requester_id, context, timestamp) VALUES (%s, %s, %s, NOW())",
            (user_id, requester_id, requester_role)
        )
        
        # Log access to access_log (new)
        cur.execute("""
            INSERT INTO access_log (student_id, requester_id, action, resource_accessed, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            requester_id,
            'Profile Data Accessed',
            f"Profile Types: {', '.join(profile_types)}",
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        
        conn.commit()

        return jsonify(profiles), 200
    except Exception as e:
        print(f"Error fetching profile: {e}")
        return jsonify({'error': 'Error fetching profile'}), 500

@app.route('/rules', methods=['POST'])
def add_rule():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        # identity = request.identity
        data = request.get_json()

        cur.execute(
            "INSERT INTO access_rules (user_id, role, profile_type) VALUES (%s, %s, %s)",
            (data['id'], data['role'], data['profile_type'])
        )
        conn.commit()

        return jsonify({'message': 'Rule added'}), 201
    except Exception as e:
        print(f"Error adding rule: {e}")
        return jsonify({'error': 'Error adding rule'}), 500

@app.route('/audit', methods=['GET'])
def get_audit_logs():
    role = request.args.get('role')
    if role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs")
        logs = cur.fetchall()

        return jsonify([
            {
                'user_id': log['user_id'],
                'requester_id': log['requester_id'],
                'context': log['context'],
                'timestamp': log['timestamp'].isoformat()
            } for log in logs
        ]), 200
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return jsonify({'error': 'Error fetching logs'}), 500

@app.route('/admin/user_management', methods=['GET'])
def user_management():
    # This route can be used to display user management page
    return render_template('admin/user_management.html')

@app.route("/admin/add_user", methods=["GET", "POST"])
def add_user():
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        cur.execute("SELECT user_id, full_name, email, role, contact_no, student_id, department, status FROM users") 
        users_data = cur.fetchall()
        print(f"Fetched users: {users_data}")
        
        # Add a default status for each user if status column doesn't exist
        for user in users_data:
            if 'status' not in user:
                user['status'] = 'Active'
        
        roles = [
            ("", "Select Role"),
            ("Admin", "Admin"),
            ("Requester", "Requester"),
            ("Student", "Student"),
            ("Third_Party", "3rd Party")
        ]

        return render_template(
            'admin/add_user.html',
            roles=roles,
            users=users_data
        )
                
    except Exception as e:
        print(f"Error fetching users: {e}")
        users_data = []
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    

@app.route('/admin/edit_user', methods=['POST'])
def edit_user():
    """Handle editing user details"""
    print("Edit user route called")
    user_role = session.get('role')
    print(f"User role: {user_role}")
    if user_role not in ['admin', 'Admin']:
        print("User not admin, redirecting to login")
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get form data
        user_id = request.form.get('user_id')
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        student_id = request.form.get('student_id', '').strip()
        department = request.form.get('department', 'General').strip()
        status = request.form.get('status', '1')
        
        print(f"Form data received: user_id={user_id}, full_name={full_name}, email={email}, role={role}")
        print(f"All form data: {dict(request.form)}")
        
        # Validate required fields
        if not all([user_id, full_name, email, role]):
            return handle_error('All required fields must be filled', 'Validation Error', 400)
        
        # Check if email is already taken by another user
        cur.execute("SELECT user_id FROM users WHERE email = %s AND user_id != %s", (email, user_id))
        existing_user = cur.fetchone()
        if existing_user:
            return handle_error('Email already taken by another user', 'Validation Error', 409)
        
        # Check if student ID is already taken by another user (for students)
        if role == 'Student' and student_id:
            cur.execute("SELECT user_id FROM users WHERE student_id = %s AND user_id != %s", (student_id, user_id))
            existing_student = cur.fetchone()
            if existing_student:
                return handle_error('Student ID already taken by another user', 'Validation Error', 409)
        
        # Update user information
        cur.execute("""
            UPDATE users 
            SET full_name = %s, email = %s, role = %s, contact_no = %s, 
                student_id = %s, department = %s, status = %s
            WHERE user_id = %s
        """, (full_name, email, role, contact_number, student_id, department, status, user_id))
        
        conn.commit()
        return redirect(url_for('add_user'))
        
    except Exception as e:
        print(f"Error updating user: {e}")
        if conn:
            conn.rollback()
        return handle_error('Failed to update user', 'Update Error', 500)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/users')
def users():
    # Redirect to add_user screen which will show all users
    return redirect(url_for('add_user'))

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    # Check if user is admin
    user_role = session.get('role')
    print(f"Admin settings - Session role: {user_role}")
    if user_role not in ['admin', 'Admin']:
        print("User is not admin, redirecting to login")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle settings form submission
        password_requirements = request.form.get('password_requirements')
        two_factor_auth = request.form.get('two_factor_auth')
        email_notifications = request.form.get('email_notifications')
        in_app_notifications = request.form.get('in_app_notifications')
        third_party_services = request.form.get('third_party_services')
        
        # Here you would save these settings to database
        print(f"Settings updated: {password_requirements}, {two_factor_auth}, {email_notifications}, {in_app_notifications}, {third_party_services}")
        
        return redirect(url_for('admin_settings'))
    
    # Get current admin user info for display
    conn = None
    cur = None
    admin_info = None
    
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        cur.execute("SELECT full_name, email, role FROM users WHERE user_id = %s", (session.get('user_id'),))
        admin_info = cur.fetchone()
    except Exception as e:
        print(f"Error fetching admin info: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('admin/settings.html', admin_info=admin_info)

@app.route('/admin/update_info', methods=['POST'])
def admin_update_info():
    # Check if user is admin
    user_role = session.get('role')
    if user_role not in ['admin', 'Admin']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        contact_no = request.form.get('contact_no')
        
        # Update admin information
        cur.execute("""
            UPDATE users 
            SET full_name = %s, email = %s, contact_no = %s 
            WHERE user_id = %s
        """, (full_name, email, contact_no, session.get('user_id')))
        
        conn.commit()
        print(f"Admin info updated: {full_name}, {email}, {contact_no}")
        
    except Exception as e:
        print(f"Error updating admin info: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for('admin_settings'))

@app.route('/admin/change_password', methods=['POST'])
def admin_change_password():
    # Check if user is admin
    user_role = session.get('role')
    if user_role not in ['admin', 'Admin']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        
        # Validate passwords match
        if new_password != confirm_new_password:
            print("New passwords do not match")
            return redirect(url_for('admin_settings'))
        
        # Get current user's password
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (session.get('user_id'),))
        user = cur.fetchone()
        
        if not user:
            print("User not found")
            return redirect(url_for('admin_settings'))
        
        # Verify current password
        current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if user['password_hash'] != current_password_hash:
            print("Current password is incorrect")
            return redirect(url_for('admin_settings'))
        
        # Update password
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cur.execute("""
            UPDATE users 
            SET password_hash = %s 
            WHERE user_id = %s
        """, (new_password_hash, session.get('user_id')))
        
        conn.commit()
        print("Admin password updated successfully")
        
    except Exception as e:
        print(f"Error changing admin password: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return redirect(url_for('admin_settings'))

@app.route('/admin/access_logs', methods=['GET'])
def admin_access_logs():
    # Check if user is admin
    user_role = session.get('role')
    print(f"Admin access logs - Session role: {user_role}")
    if user_role not in ['admin', 'Admin']:
        print("User is not admin, redirecting to login")
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get search and filter parameters
        search_query = request.args.get('q', '')
        date_filter = request.args.get('date', '')
        action_filter = request.args.get('action', '')
        
        # Build the query
        query = """
            SELECT al.access_timestamp, u.full_name, al.action, al.resource_accessed, al.ip_address
            FROM access_log al
            JOIN users u ON al.requester_id = u.user_id
        """
        params = []
        
        # Add search filter
        if search_query:
            query += " WHERE (u.full_name LIKE %s OR al.resource_accessed LIKE %s OR al.ip_address LIKE %s)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param, search_param])
        
        # Add date filter
        if date_filter:
            if search_query:
                query += " AND DATE(al.access_timestamp) = %s"
            else:
                query += " WHERE DATE(al.access_timestamp) = %s"
            params.append(date_filter)
        
        # Add action filter
        if action_filter:
            if search_query or date_filter:
                query += " AND al.action = %s"
            else:
                query += " WHERE al.action = %s"
            params.append(action_filter)
        
        query += " ORDER BY al.access_timestamp DESC LIMIT 100"
        
        cur.execute(query, params)
        access_logs = cur.fetchall()
        print(f"Fetched {len(access_logs)} access logs")
        
    except Exception as e:
        print(f"Error fetching access logs: {e}")
        access_logs = []
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('admin/access_log.html', 
                         access_logs=access_logs,
                         search_query=search_query,
                         date_filter=date_filter,
                         action_filter=action_filter)

@app.route('/admin/dashboard')
def admin_dashboard():
    # Check if user is admin
    user_role = session.get('role')
    print(f"Admin dashboard - Session role: {user_role}")
    if user_role not in ['admin', 'Admin']:
        print("User is not admin, redirecting to login")
        return redirect(url_for('login'))
        
    conn = None
    cur = None
    
    try:  
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            charset='utf8mb4'
        )
        cur = conn.cursor()
        
        # Get KPI data
        # Total users
        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]
        print(f"Total users: {total_users}")
        # Total students
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
        total_students = cur.fetchone()[0]
        
        # Total requesters
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'requester'")
        total_requesters = cur.fetchone()[0]
        
        # Get recent activity logs (last 10)
        cur.execute("""
            SELECT al.access_timestamp, u.full_name, al.action, al.resource_accessed
            FROM access_log al
            JOIN users u ON al.requester_id = u.user_id
            ORDER BY al.access_timestamp DESC
            LIMIT 10
        """)
        recent_logs = cur.fetchall()
        
        # Get activity trends data (last 7 days)
        cur.execute("""
            SELECT DATE(access_timestamp) as date, COUNT(*) as count
            FROM access_log
            WHERE access_timestamp >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(access_timestamp)
            ORDER BY date
        """)
        activity_trends = cur.fetchall()
        
        # Get login attempts trend (last 7 days)
        cur.execute("""
            SELECT DATE(login_timestamp) as date, COUNT(*) as count
            FROM login_attempts
            WHERE login_timestamp >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(login_timestamp)
            ORDER BY date
        """)
        login_attempts_trends = cur.fetchall()
        
        # Fetch user information for greeting
        user = None
        try:
            admin_id = session.get('user_id')
            print(f"Admin ID: {admin_id}")
            if admin_id:
                cur.execute("SELECT full_name, email FROM users WHERE user_id = %s", (admin_id,))
                user = cur.fetchone()
                print(f"User: {user}")
        except Exception as e:
            print(f"Error fetching user info: {e}")
        
        return render_template('admin/admin.html', 
                             total_users=total_users,
                             total_students=total_students,
                             total_requesters=total_requesters,
                             recent_logs=recent_logs,
                             activity_trends=activity_trends,
                             login_attempts_trends=login_attempts_trends,
                             user=user)
        
    except Exception as e:
        print(f"Error in admin_dashboard: {e}")
        return render_template('admin/admin.html', 
                             total_users=0,
                             total_students=0,
                             total_requesters=0,
                             recent_logs=[],
                             activity_trends=[],
                             login_attempts_trends=[],
                             user=None)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/students/dashboard')
def students():
    conn = None
    cur = None
    recent_logs = []
    incoming_requests = []
    
    try:
        student_id = session.get('user_id')
        if not student_id:
            return redirect(url_for('login'))
            
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Fetch latest 5 access logs for the current student
        cur.execute("""
            SELECT 
                al.log_id,
                al.action,
                al.resource_accessed,
                al.access_timestamp,
                u.full_name as requester_name,
                u.role as requester_role
            FROM access_log al
            LEFT JOIN users u ON al.requester_id = u.user_id
            WHERE al.student_id = %s
            ORDER BY al.access_timestamp DESC
            LIMIT 5
        """, (student_id,))
        recent_logs = cur.fetchall()
        cur.close()
        # Fetch incoming requests (pending status)

        cur1 = conn.cursor()
        cur1.execute("""
            SELECT 
                ar.request_id,
                ar.requester_id,
                ar.requested_data,
                ar.status,
                ar.request_date,
                u.full_name as requester_name,
                u.role as requester_role,
                u.department as requester_department
            FROM access_requests ar
            LEFT JOIN users u ON ar.requester_id = u.user_id
            WHERE ar.student_id = %s AND ar.status = 'pending'
            ORDER BY ar.request_date DESC
        """, (student_id,))
        incoming_requests = cur1.fetchall()
        cur1.close()
        print(f"Fetched {len(recent_logs)} recent access logs and {len(incoming_requests)} incoming requests for dashboard")

            # Fetch user information for greeting
        user = None
        cur2 = conn.cursor()
        cur2.execute("SELECT full_name, email FROM users WHERE user_id = %s", (student_id,))
        user = cur2.fetchone()
        conn.close()
        return render_template('students/dashboard.html', 
                            recent_logs=recent_logs, 
                            incoming_requests=incoming_requests,
                            user=user)
        
    except Exception as e:
        print(f"Error fetching dashboard data: {e}")
    


@app.route('/students/create_profile')
def create_students():
    conn = None
    cur = None
    student_data = {}
    
    try:
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
            
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Fetch existing student data from all tables
        cur.execute("""
            SELECT 
                pi.full_name,
                pi.email,
                pi.phone,
                pi.birth_date,
                pi.gender,
                pi.relationship_status,
                ai.student_id,
                ai.major,
                ai.year,
                ai.gpa,
                ai.advisor,
                ci.address,
                ci.contact_phone,
                ci.city,
                ci.state,
                ai.linkedin_url,
                ai.github_url,
                adi.emergency_contact
            FROM personal_information pi
            LEFT JOIN academic_information ai ON pi.user_id = ai.user_id
            LEFT JOIN contact_information ci ON pi.user_id = ci.user_id
            LEFT JOIN additional_information adi ON pi.user_id = adi.user_id
            WHERE pi.user_id = %s
        """, (user_id,))
        
        result = cur.fetchone()
        if result:
            student_data = result
            
    except Exception as e:
        print(f"Error fetching student data: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('students/create_student.html', student_data=student_data)

@app.route('/students/documents')
def documents():
    return render_template('students/document_upload.html')

@app.route('/students/access_logs')
def access_logs():
    conn = None
    cur = None
    access_logs_data = []
    
    try:
        student_id = session.get('user_id')
        if not student_id:
            return redirect(url_for('login'))
            
        # Get search and filter parameters
        search_query = request.args.get('q', '').strip()
        date_filter = request.args.get('date', '')
        data_filter = request.args.get('data', '')
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Build the base query
        base_query = """
            SELECT 
                al.log_id,
                al.action,
                al.resource_accessed,
                al.access_timestamp,
                al.ip_address,
                u.full_name as requester_name,
                u.role as requester_role,
                u.department as requester_department
            FROM access_log al
            LEFT JOIN users u ON al.requester_id = u.user_id
            WHERE al.student_id = %s
        """
        
        params = [student_id]
        
        # Add search filter
        if search_query:
            base_query += " AND (u.full_name LIKE %s OR al.action LIKE %s OR al.resource_accessed LIKE %s)"
            search_term = f"%{search_query}%"
            params.extend([search_term, search_term, search_term])
        
        # Add date filter
        if date_filter:
            if date_filter == 'today':
                base_query += " AND DATE(al.access_timestamp) = CURDATE()"
            elif date_filter == 'week':
                base_query += " AND al.access_timestamp >= DATE_SUB(NOW(), INTERVAL 1 WEEK)"
            elif date_filter == 'month':
                base_query += " AND al.access_timestamp >= DATE_SUB(NOW(), INTERVAL 1 MONTH)"
            elif date_filter == 'year':
                base_query += " AND al.access_timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR)"
        
        # Add data type filter
        if data_filter:
            base_query += " AND al.resource_accessed LIKE %s"
            data_term = f"%{data_filter}%"
            params.append(data_term)
        
        # Add ordering
        base_query += " ORDER BY al.access_timestamp DESC"
        
        cur.execute(base_query, params)
        access_logs_data = cur.fetchall()
        
        print(f"Fetched access logs with filters - Search: '{search_query}', Date: '{date_filter}', Data: '{data_filter}': {len(access_logs_data)} records")
        
    except Exception as e:
        print(f"Error fetching access logs: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('students/access_logs.html', 
                         access_logs=access_logs_data,
                         search_query=search_query,
                         date_filter=date_filter,
                         data_filter=data_filter)


@app.route('/students/access_request')
def access_request():
    conn = None
    cur = None
    incoming_requests = []
    past_requests = []
    
    try:
        student_id = session.get('user_id')
        if not student_id:
            return redirect(url_for('login'))
            
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Fetch incoming requests (pending status)
        cur.execute("""
            SELECT 
                ar.request_id,
                ar.requester_id,
                ar.requested_data,
                ar.status,
                ar.request_date,
                u.full_name as requester_name,
                u.role as requester_role,
                u.department as requester_department
            FROM access_requests ar
            LEFT JOIN users u ON ar.requester_id = u.user_id
            WHERE ar.student_id = %s AND ar.status = 'pending'
            ORDER BY ar.request_date DESC
        """, (student_id,))
        incoming_requests = cur.fetchall()
        
        # Fetch past requests (approved/rejected status)
        cur.execute("""
            SELECT 
                ar.request_id,
                ar.requester_id,
                ar.requested_data,
                ar.status,
                ar.request_date,
                u.full_name as requester_name,
                u.role as requester_role,
                u.department as requester_department
            FROM access_requests ar
            LEFT JOIN users u ON ar.requester_id = u.user_id
            WHERE ar.student_id = %s AND ar.status IN ('approved', 'rejected')
            ORDER BY ar.request_date DESC
        """, (student_id,))
        past_requests = cur.fetchall()
        
        print(f"Incoming requests: {incoming_requests}")
        print(f"Past requests: {past_requests}")
        
    except Exception as e:
        print(f"Error fetching access requests: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('students/access_requests.html', 
                         incoming_requests=incoming_requests, 
                         past_requests=past_requests)

@app.route('/update_request_status', methods=['POST'])
def update_request_status():
    conn = None
    cur = None
    
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        status = data.get('status')
        student_id = session.get('user_id')
        
        if not student_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
            
        if not request_id or not status:
            return jsonify({'success': False, 'error': 'Missing request_id or status'}), 400
            
        if status not in ['approved', 'rejected']:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
            
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Verify that the request belongs to the current student
        cur.execute("""
            SELECT student_id FROM access_requests 
            WHERE request_id = %s AND student_id = %s
        """, (request_id, student_id))
        
        if not cur.fetchone():
            return jsonify({'success': False, 'error': 'Request not found or unauthorized'}), 403
            
        # Update the request status
        cur.execute("""
            UPDATE access_requests 
            SET status = %s 
            WHERE request_id = %s AND student_id = %s
        """, (status, request_id, student_id))
        
        conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error updating request status: {e}")
        return jsonify({'success': False, 'error': 'Database error'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/students/privacy_settings')
def privacy_settings():
    return render_template('students/privacy_setting.html')

@app.route('/students/settings')
def settings():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    user = None
    try:
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        cur.execute("SELECT full_name, email, contact_no FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
    except Exception as e:
        print(f"Error loading student settings: {e}")
        user = None
    finally:
        conn.close()

    return render_template('students/setting.html', user=user)

@app.route('/students/settings/update_info', methods=['POST'])
def student_update_info():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact_no = request.form.get('contact_no', '').strip()

        cur.execute(
            "UPDATE users SET full_name = %s, email = %s, contact_no = %s WHERE user_id = %s",
            (full_name, email, contact_no, user_id)
        )
        conn.commit()
        return redirect(url_for('settings'))
    except Exception as e:
        print(f"Error updating student info: {e}")
        return redirect(url_for('settings'))
    finally:
        conn.close()

@app.route('/students/settings/change_password', methods=['POST'])
def student_change_password():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')

        if not new_password or new_password != confirm_new_password:
            return redirect(url_for('settings'))

        # Verify current password
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            return redirect(url_for('settings'))

        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if row['password_hash'] != current_hash:
            return redirect(url_for('settings'))

        # Update to new password hash
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (new_hash, user_id))
        conn.commit()
        return redirect(url_for('settings'))
    except Exception as e:
        print(f"Error changing password: {e}")
        return redirect(url_for('settings'))
    finally:
        conn.close()

@app.route('/requester')
def requester():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    try:
        requester_id = session.get('user_id')
        if not requester_id:
            return redirect(url_for('login'))

        # Optional filters for the home 'Students' section
        status_filter_home = request.args.get('status')
        query_text = request.args.get('q')

        cur.execute("""
            SELECT status, COUNT(*) AS cnt
            FROM access_requests
            WHERE requester_id = %s
            GROUP BY status
        """, (requester_id,))
        rows = cur.fetchall()

        pending_count = 0
        approved_count = 0
        rejected_count = 0
        for row in rows:
            if row['status'] == 'pending':
                pending_count = row['cnt']
            elif row['status'] == 'approved':
                approved_count = row['cnt']
            elif row['status'] == 'rejected':
                rejected_count = row['cnt']

        # Recent 5 requests for the 'Students' section (optionally filtered)
        recent_query = (
            """
            SELECT 
                ar.request_id,
                ar.student_id,
                ar.requested_data,
                ar.status,
                ar.request_date,
                u.full_name as student_name
            FROM access_requests ar
            LEFT JOIN users u ON ar.student_id = u.user_id
            WHERE ar.requester_id = %s
            """
        )
        params = [requester_id]
        if status_filter_home in ['pending', 'approved', 'rejected']:
            recent_query += " AND ar.status = %s"
            params.append(status_filter_home)
        if query_text:
            recent_query += " AND (u.full_name LIKE %s OR CAST(ar.student_id AS CHAR) LIKE %s)"
            like_term = f"%{query_text}%"
            params.extend([like_term, like_term])
        recent_query += " ORDER BY ar.request_date DESC LIMIT 5"
        cur.execute(recent_query, params)
        recent_requests = cur.fetchall()

        # Fetch user information for greeting
        user = None
  
        requester_id = session.get('user_id')
        if requester_id:
            print(f"Requester ID: {requester_id}")
            cur.execute("SELECT full_name, email FROM users WHERE user_id = %s", (requester_id,))
            user = cur.fetchone()
            print(f"User: {user}")
        conn.close()

        return render_template(
            'requester/home.html',
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            recent_requests=recent_requests,
            active_status_home=status_filter_home or 'all',
                q=query_text or '',
                user=user
            )

    except Exception as e:
        print(f"Error fetching requester KPIs: {e}")
        pending_count = 0
        approved_count = 0
        rejected_count = 0
        recent_requests = []
        status_filter_home = None
        query_text = None
    

@app.route('/admin/resources')
def admin_resources():
    return render_template('admin/resources.html')

@app.route('/create_profile', methods=["POST"])
def create_profile():
    conn = None
    cur = None
    cur1 = None
    cur2 = None
    cur3 = None
    try:
        conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
        cur = conn.cursor()
        email = request.form.get("email")
        full_name = request.form.get("full_name")
        contact_number = request.form.get("contact_number")
        gender = request.form.get("gender")
        relationship_status = request.form.get("relationship_status")
        student_id = request.form.get("student_id")
        major = request.form.get("major")
        year = request.form.get("year")
        birth_date = request.form.get("birth_date")
        gpa = request.form.get("gpa")
        advisor = request.form.get("advisor")
        address = request.form.get("address")
        contact_phone = request.form.get("contact_phone")
        city = request.form.get("city")
        state = request.form.get("state")
        linkedin_url = request.form.get("linkedin_url")
        github_url = request.form.get("github_url")
        emergency_contact = request.form.get("emergency_contact")
        user_id = session.get('user_id')
        print(f"Received data: email={email}, full_name={full_name}, contact_number={contact_number}, gender={gender}, relationship_status={relationship_status}, student_id={student_id}, major={major}, year={year}, birth_date={birth_date}, gpa={gpa}, advisor={advisor}, address={address}, contact_phone={contact_phone}, city={city}, state={state}, linkedin_url={linkedin_url}, github_url={github_url}, emergency_contact={emergency_contact}")
        print(f"User ID from session: {user_id}")
        if not user_id:
            return redirect(url_for('login')) # Redirect to login if user_id is not set
         # Insert or update personal information
        cur.execute("""
            INSERT INTO personal_information (user_id, full_name, email, phone, birth_date, gender, relationship_status) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            full_name = VALUES(full_name),
            email = VALUES(email),
            phone = VALUES(phone),
            birth_date = VALUES(birth_date),
            gender = VALUES(gender),
            relationship_status = VALUES(relationship_status)
        """, (user_id, full_name, email, contact_number, birth_date, gender, relationship_status))
        cur.close()
        
        cur1 = conn.cursor()
        cur1.execute("""
            INSERT INTO academic_information (user_id, student_id, major, year, gpa, advisor, linkedin_url, github_url) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            student_id = VALUES(student_id),
            major = VALUES(major),
            year = VALUES(year),
            gpa = VALUES(gpa),
            advisor = VALUES(advisor),
            linkedin_url = VALUES(linkedin_url),
            github_url = VALUES(github_url)
        """, (user_id, student_id, major, year, gpa, advisor, linkedin_url, github_url))
        cur1.close()
        
        cur2 = conn.cursor()
        cur2.execute("""
            INSERT INTO contact_information (user_id, address, contact_phone, city, state) 
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            address = VALUES(address),
            contact_phone = VALUES(contact_phone),
            city = VALUES(city),
            state = VALUES(state)
        """, (user_id, address, contact_phone, city, state))
        cur2.close()
        
        cur3 = conn.cursor()
        cur3.execute("""
            INSERT INTO additional_information (user_id, emergency_contact) 
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE 
            emergency_contact = VALUES(emergency_contact)
        """, (user_id, emergency_contact))
        cur3.close()
        
        conn.commit()  
        conn.close()
        return redirect(url_for('students'))
    except Exception as e:
        if cur:
            cur.close()
        if cur1:
            cur1.close()
        if cur2:
            cur2.close()
        if cur3:
            cur3.close()
        if conn:
            conn.close()
        print(f"Error connecting to database: {e}")
        return jsonify({'error': 'Database connection error'}), 500
    
    return render_template('students/create_student.html')

@app.route('/requester/requests')
def requester_status():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    try:
        requester_id = session.get('user_id')
        if not requester_id:
            return redirect(url_for('login'))
        
        # Optional status filter
        status_filter = request.args.get('status')
        
        # Fetch access requests for the current requester with student information
        base_query = (
            """
            SELECT 
                ar.request_id,
                ar.requester_id,
                ar.student_id,
                ar.requested_data,
                ar.status,
                ar.request_date,
                u.full_name as student_name,
                u.email as student_email
            FROM access_requests ar
            LEFT JOIN users u ON ar.student_id = u.user_id
            WHERE ar.requester_id = %s
            """
        )

        params = [requester_id]
        if status_filter in ['pending', 'approved', 'rejected']:
            base_query += " AND ar.status = %s"
            params.append(status_filter)

        base_query += " ORDER BY ar.request_date DESC"

        cur.execute(base_query, params)
        
        requests_data = cur.fetchall()
        print(f"Fetched requests: {requests_data}")
        
    except Exception as e:
        print(f"Error fetching requests: {e}")
        requests_data = []
    finally:
        conn.close()

    return render_template('requester/request_status.html', requests=requests_data, active_status=status_filter or 'all')

@app.route('/requester/students')
def requester_students():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    try:
        requester_id = session.get('user_id')
        if not requester_id:
            return redirect(url_for('login'))
        
        # Get search query
        search_query = request.args.get('q', '').strip()
        
        # Build the base query
        base_query = """
            SELECT 
                u.user_id,
                u.full_name,
                u.email,
                u.contact_no,
                u.student_id,
                u.department,
                u.status,
                pi.full_name as personal_name,
                pi.birth_date,
                ai.major,
                ai.year,
                ai.gpa,
                ai.advisor,
                ci.address,
                ci.city,
                ci.state,
                adi.emergency_contact,
                pi.relationship_status
            FROM users u
            LEFT JOIN personal_information pi ON u.user_id = pi.user_id
            LEFT JOIN academic_information ai ON u.user_id = ai.user_id
            LEFT JOIN contact_information ci ON u.user_id = ci.user_id
            LEFT JOIN additional_information adi ON u.user_id = adi.user_id
            WHERE u.role = 'Student'
        """
        
        params = []
        
        # Add search filter if provided
        if search_query:
            base_query += """
                AND (u.full_name LIKE %s 
                     OR u.student_id LIKE %s 
                     OR ai.major LIKE %s 
                     OR u.department LIKE %s
                     OR u.email LIKE %s)
            """
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param, search_param, search_param, search_param])
        
        base_query += " ORDER BY u.full_name"
        
        cur.execute(base_query, params)
        students_data = cur.fetchall()
        
        # Fetch existing requests for each student
        for student in students_data:
            cur.execute("""
                SELECT requested_data, status
                FROM access_requests 
                WHERE requester_id = %s AND student_id = %s
                ORDER BY request_date DESC
            """, (requester_id, student['user_id']))
            existing_requests = cur.fetchall()
            student['existing_requests'] = existing_requests
            student['requested_data_points'] = [req['requested_data'] for req in existing_requests]
            student['has_pending_requests'] = any(req['status'] == 'pending' for req in existing_requests)
            student['has_approved_requests'] = any(req['status'] == 'approved' for req in existing_requests)
        
        print(f"Fetched students with requests: {students_data}")
        
        # Log the access to student profiles
        for student in students_data:
            cur.execute("""
                INSERT INTO access_log (student_id, requester_id, action, resource_accessed, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                student['user_id'],
                requester_id,
                'Profile Viewed',
                'Student Profile List',
                request.remote_addr,
                request.headers.get('User-Agent', '')
            ))
        
        conn.commit()
        
    except Exception as e:
        print(f"Error fetching students: {e}")
        students_data = []
    finally:
        conn.close()

    return render_template('requester/view_student.html', students=students_data, q=search_query)

@app.route('/requester/approved_data/<int:student_id>')
def view_approved_data(student_id):
    conn = None
    cur = None
    approved_data = {}
    
    try:
        requester_id = session.get('user_id')
        if not requester_id:
            return redirect(url_for('login'))
            
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get student basic info
        cur.execute("""
            SELECT user_id, full_name, email, student_id, department
            FROM users 
            WHERE user_id = %s AND role = 'Student'
        """, (student_id,))
        student_info = cur.fetchone()
        
        if not student_info:
            return "Student not found", 404
            
        # Get approved requests for this student
        cur.execute("""
            SELECT requested_data, request_date
            FROM access_requests 
            WHERE requester_id = %s AND student_id = %s AND status = 'approved'
            ORDER BY request_date DESC
        """, (requester_id, student_id))
        approved_requests = cur.fetchall()
        
        if not approved_requests:
            return "No approved requests found for this student", 404
            
        # Get approved data points
        approved_data_points = [req['requested_data'] for req in approved_requests]
        
        # Fetch personal information if approved
        if 'personal_information' in approved_data_points:
            cur.execute("""
                SELECT full_name, birth_date, phone, email
                FROM personal_information 
                WHERE user_id = %s
            """, (student_id,))
            approved_data['personal_information'] = cur.fetchone()
            
        # Fetch academic information if approved
        if 'academic_information' in approved_data_points:
            cur.execute("""
                SELECT major, year, gpa, advisor
                FROM academic_information 
                WHERE user_id = %s
            """, (student_id,))
            approved_data['academic_information'] = cur.fetchone()
            
        # Fetch contact information if approved
        if 'contact_information' in approved_data_points:
            cur.execute("""
                SELECT address, city, state, contact_phone
                FROM contact_information 
                WHERE user_id = %s
            """, (student_id,))
            approved_data['contact_information'] = cur.fetchone()
            
        # Fetch additional information if approved
        if 'additional_information' in approved_data_points:
            cur.execute("""
                SELECT emergency_contact, relationship
                FROM additional_information 
                WHERE user_id = %s
            """, (student_id,))
            approved_data['additional_information'] = cur.fetchone()
        
        # Log the access to approved data
        cur.execute("""
            INSERT INTO access_log (student_id, requester_id, action, resource_accessed, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            student_id,
            requester_id,
            'Approved Data Viewed',
            f"Approved Data: {', '.join(approved_data_points)}",
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        
        conn.commit()
        
        print(f"Fetched approved data for student {student_id}: {approved_data}")
        
    except Exception as e:
        print(f"Error fetching approved data: {e}")
        return "Error fetching approved data", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('requester/approved_data.html', 
                         student_info=student_info, 
                         approved_data=approved_data,
                         approved_data_points=approved_data_points)

@app.route('/requester/settings')
def requester_settings():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    user = None
    try:
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        cur.execute("SELECT full_name, email, contact_no FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
    except Exception as e:
        print(f"Error loading requester settings: {e}")
        user = None
    finally:
        conn.close()

    return render_template('requester/settings.html', user=user)

@app.route('/requester/settings/update_info', methods=['POST'])
def requester_update_info():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact_no = request.form.get('contact_no', '').strip()

        cur.execute(
            "UPDATE users SET full_name = %s, email = %s, contact_no = %s WHERE user_id = %s",
            (full_name, email, contact_no, user_id)
        )
        conn.commit()
        return redirect(url_for('requester_settings'))
    except Exception as e:
        print(f"Error updating requester info: {e}")
        return redirect(url_for('requester_settings'))
    finally:
        conn.close()

@app.route('/requester/settings/change_password', methods=['POST'])
def requester_change_password():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')

        if not new_password or new_password != confirm_new_password:
            return redirect(url_for('requester_settings'))

        # Verify current password
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            return redirect(url_for('requester_settings'))

        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if row['password_hash'] != current_hash:
            return redirect(url_for('requester_settings'))

        # Update to new password hash
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (new_hash, user_id))
        conn.commit()
        return redirect(url_for('requester_settings'))
    except Exception as e:
        print(f"Error changing password: {e}")
        return redirect(url_for('requester_settings'))
    finally:
        conn.close()

@app.route('/requester/add_student')
def add_student():
    return render_template('requester/add_students.html')

@app.route('/submit_access_request', methods=['POST'])
def submit_access_request():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        cur = conn.cursor()
        student_id = request.form.get('student_id')
        data_points = request.form.getlist('data_points')  # Get all selected checkboxes
        requester_id = session.get('user_id')
        
        if not data_points:
            return handle_error('Please select at least one data point', 'Validation Error', 400)
        
        # Create access_requests table if it doesn't exist
        cur.execute("""
            CREATE TABLE IF NOT EXISTS access_requests (
                request_id INT AUTO_INCREMENT PRIMARY KEY,
                requester_id INT NOT NULL,
                student_id INT NOT NULL,
                requested_data VARCHAR(255) NOT NULL,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (requester_id) REFERENCES users(user_id),
                FOREIGN KEY (student_id) REFERENCES users(user_id)
            )
        """)
        
        # Create access_log table if it doesn't exist
        cur.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                log_id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                requester_id INT NOT NULL,
                action VARCHAR(100) NOT NULL,
                resource_accessed VARCHAR(255),
                access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                user_agent TEXT,
                FOREIGN KEY (student_id) REFERENCES users(user_id),
                FOREIGN KEY (requester_id) REFERENCES users(user_id)
            )
        """)
        conn.commit()
        
        # Get existing requests for this student
        cur.execute("""
            SELECT requested_data, status 
            FROM access_requests 
            WHERE requester_id = %s AND student_id = %s
        """, (requester_id, student_id))
        existing_requests = cur.fetchall()
        existing_data_points = [req['requested_data'] for req in existing_requests]
        
        # Find new data points to add
        new_data_points = [dp for dp in data_points if dp not in existing_data_points]
        
        # Find data points to remove (existing but not in current selection)
        data_points_to_remove = [dp for dp in existing_data_points if dp not in data_points]
        
        # Remove deselected data points (only if they are pending)
        for data_point in data_points_to_remove:
            cur.execute("""
                DELETE FROM access_requests 
                WHERE requester_id = %s AND student_id = %s AND requested_data = %s AND status = 'pending'
            """, (requester_id, student_id, data_point))
        
        # Add new data points
        for data_point in new_data_points:
            cur.execute("""
                INSERT INTO access_requests (requester_id, student_id, requested_data, status, request_date) 
                VALUES (%s, %s, %s, %s, NOW())
            """, (requester_id, student_id, data_point, 'pending'))
        
        conn.commit()
        print(f"Access request updated for student {student_id}. Added: {new_data_points}, Removed: {data_points_to_remove}")
        
        return redirect(url_for('requester_status'))
        
    except Exception as e:
        print(f"Error submitting access request: {e}")
        return handle_error('Error submitting access request', 'Request Error', 500)
    finally:
        conn.close()


# Third Party Routes
@app.route('/third-party/dashboard')
def third_party_dashboard():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        third_party_id = session.get('user_id')
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get request counts
        cur.execute("""
            SELECT 
                COUNT(*) as total_count,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count
            FROM access_requests 
            WHERE requester_id = %s
        """, (third_party_id,))
        counts = cur.fetchone()
        
        # Ensure counts are integers, not None
        if counts:
            counts['total_count'] = counts['total_count'] or 0
            counts['pending_count'] = counts['pending_count'] or 0
            counts['approved_count'] = counts['approved_count'] or 0
            counts['rejected_count'] = counts['rejected_count'] or 0
        else:
            counts = {'total_count': 0, 'pending_count': 0, 'approved_count': 0, 'rejected_count': 0}
        
        # Get recent requests
        cur.execute("""
            SELECT ar.*, u.full_name as student_name
            FROM access_requests ar
            JOIN users u ON ar.student_id = u.user_id
            WHERE ar.requester_id = %s
            ORDER BY ar.request_date DESC
            LIMIT 5
        """, (third_party_id,))
        recent_requests = cur.fetchall()
        
        # Get user information for greeting
        user = None
        try:
            cur.execute("SELECT full_name, email FROM users WHERE user_id = %s", (third_party_id,))
            user = cur.fetchone()
        except Exception as e:
            print(f"Error fetching user info: {e}")
        
    except Exception as e:
        print(f"Error in third_party_dashboard: {e}")
        counts = {'total_count': 0, 'pending_count': 0, 'approved_count': 0, 'rejected_count': 0}
        recent_requests = []
        user = None
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('third_party/dashboard.html',
                         total_count=counts['total_count'],
                         pending_count=counts['pending_count'],
                         approved_count=counts['approved_count'],
                         rejected_count=counts['rejected_count'],
                         recent_requests=recent_requests,
                         user=user)

@app.route('/third-party/requests')
def third_party_requests():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        third_party_id = session.get('user_id')
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get all requests
        cur.execute("""
            SELECT ar.*, u.full_name as student_name
            FROM access_requests ar
            JOIN users u ON ar.student_id = u.user_id
            WHERE ar.requester_id = %s
            ORDER BY ar.request_date DESC
        """, (third_party_id,))
        all_requests = cur.fetchall()
        
        # Filter by status
        pending_requests = [r for r in all_requests if r['status'] == 'pending']
        approved_requests = [r for r in all_requests if r['status'] == 'approved']
        rejected_requests = [r for r in all_requests if r['status'] == 'rejected']
        
    except Exception as e:
        print(f"Error in third_party_requests: {e}")
        all_requests = []
        pending_requests = []
        approved_requests = []
        rejected_requests = []
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('third_party/requests.html',
                         all_requests=all_requests,
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests)

@app.route('/third-party/api-docs')
def third_party_api_docs():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    return render_template('third_party/api_docs.html')

@app.route('/third-party/settings')
def third_party_settings():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        third_party_id = session.get('user_id')
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get user information
        cur.execute("SELECT full_name, email, contact_no FROM users WHERE user_id = %s", (third_party_id,))
        user = cur.fetchone()
        
    except Exception as e:
        print(f"Error in third_party_settings: {e}")
        user = None
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('third_party/settings.html', user=user)

@app.route('/third-party/update-info', methods=['POST'])
def third_party_update_info():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        third_party_id = session.get('user_id')
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact_no = request.form.get('contact_no', '').strip()
        
        # Update user information
        cur.execute("""
            UPDATE users 
            SET full_name = %s, email = %s, contact_no = %s
            WHERE user_id = %s
        """, (full_name, email, contact_no, third_party_id))
        
        conn.commit()
        print(f"Updated third party info: {full_name}, {email}, {contact_no}")
        
    except Exception as e:
        print(f"Error updating third party info: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return redirect(url_for('third_party_settings'))

@app.route('/third-party/change-password', methods=['POST'])
def third_party_change_password():
    # Check if user is third party
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return redirect(url_for('login'))
    
    conn = None
    cur = None
    try:
        third_party_id = session.get('user_id')
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')
        
        # Validate passwords match
        if new_password != confirm_new_password:
            print("New passwords do not match")
            return redirect(url_for('third_party_settings'))
        
        # Get current user's password
        cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (third_party_id,))
        user = cur.fetchone()
        
        if not user:
            print("User not found")
            return redirect(url_for('third_party_settings'))
        
        # Verify current password
        current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if user['password_hash'] != current_password_hash:
            print("Current password is incorrect")
            return redirect(url_for('third_party_settings'))
        
        # Update password
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cur.execute("""
            UPDATE users 
            SET password_hash = %s
            WHERE user_id = %s
        """, (new_password_hash, third_party_id))
        
        conn.commit()
        print("Third party password updated successfully")
        
    except Exception as e:
        print(f"Error changing third party password: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return redirect(url_for('third_party_settings'))

# ==================== THIRD PARTY API ENDPOINTS ====================

@app.route('/api/v1/auth/login', methods=['POST'])
def api_login():
    """Authenticate user and return temporary token for API key generation"""
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password required'}), 400
    
    email = data['email'].strip()
    password = data['password']
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check user credentials
        cur.execute("SELECT user_id, full_name, email, role FROM users WHERE email = %s AND password_hash = %s AND role = 'Third_Party'", (email, password_hash))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid credentials or not a third party user'}), 401
        
        # Generate temporary token (valid for 1 hour)
        import time
        token_data = {
            'user_id': user['user_id'],
            'email': user['email'],
            'role': user['role'],
            'exp': int(time.time()) + 3600  # 1 hour expiry
        }
        
        # Create JWT token
        token = jwt.encode(token_data, app.secret_key, algorithm='HS256')
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'user_id': user['user_id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'role': user['role']
            },
            'message': 'Authentication successful'
        })
        
    except Exception as e:
        print(f"Error in API login: {e}")
        return jsonify({'error': 'Authentication failed'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/generate-api-key', methods=['POST'])
def generate_api_key_endpoint():
    """Generate API key for authenticated third party user"""
    # Get token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Bearer token required'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode and verify token
        token_data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_id = token_data['user_id']
        user_role = token_data['role']
        
        if user_role != 'Third_Party':
            return jsonify({'error': 'Access denied. Third party role required.'}), 403
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Generate new API key
        api_key = generate_api_key()
        
        # Update user with API key
        cur.execute("UPDATE users SET api_key = %s WHERE user_id = %s", (api_key, user_id))
        conn.commit()
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'API key generated successfully'
        })
        
    except Exception as e:
        print(f"Error generating API key: {e}")
        return jsonify({'error': 'Failed to generate API key'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/generate-api-key-web', methods=['POST'])
def generate_api_key_web():
    """Generate API key for third party user via web interface (session-based)"""
    user_role = session.get('role')
    if user_role not in ['Third_Party', 'third_party']:
        return jsonify({'error': 'Access denied. Third party role required.'}), 403
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Generate new API key
        api_key = generate_api_key()
        
        # Update user with API key
        cur.execute("UPDATE users SET api_key = %s WHERE user_id = %s", (api_key, user_id))
        conn.commit()
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'API key generated successfully'
        })
        
    except Exception as e:
        print(f"Error generating API key: {e}")
        return jsonify({'error': 'Failed to generate API key'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/students', methods=['GET'])
@require_api_key
def api_get_students():
    """Get list of all students (basic info only)"""
    conn = None
    cur = None
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get basic student information
        cur.execute("""
            SELECT 
                u.user_id,
                u.full_name,
                u.email,
                u.student_id,
                u.department,
                ai.major,
                ai.year
            FROM users u
            LEFT JOIN academic_information ai ON u.user_id = ai.user_id
            WHERE u.role = 'Student' AND u.status = 1
            ORDER BY u.full_name
        """)
        
        students = cur.fetchall()
        
        return jsonify({
            'success': True,
            'students': students,
            'count': len(students)
        })
        
    except Exception as e:
        print(f"Error fetching students: {e}")
        return jsonify({'error': 'Failed to fetch students'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/students/<int:student_id>', methods=['GET'])
@require_api_key
def api_get_student_details(student_id):
    """Get basic information about a specific student (detailed info requires approved request)"""
    conn = None
    cur = None
    try:
        requester_id = request.third_party_user['user_id']
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get basic student information only (same as /students endpoint)
        cur.execute("""
            SELECT 
                u.user_id,
                u.full_name,
                u.email,
                u.student_id,
                u.department,
                ai.major,
                ai.year
            FROM users u
            LEFT JOIN academic_information ai ON u.user_id = ai.user_id
            WHERE u.user_id = %s AND u.role = 'Student' AND u.status = 1
        """, (student_id,))
        
        student = cur.fetchone()
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Check if user has any approved requests for this student
        cur.execute("""
            SELECT COUNT(*) as approved_count
            FROM access_requests 
            WHERE requester_id = %s AND student_id = %s AND status = 'approved'
        """, (requester_id, student_id))
        
        has_approved_request = cur.fetchone()['approved_count'] > 0
        
        response_data = {
            'success': True,
            'student': student,
            'has_approved_access': has_approved_request
        }
        
        if has_approved_request:
            response_data['message'] = 'You have approved access to this student. Use /api/v1/approved-data/{student_id} for detailed information.'
        else:
            response_data['message'] = 'You need to submit an access request to view detailed information. Use /api/v1/access-requests (POST) to request access.'
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Error fetching student details: {e}")
        return jsonify({'error': 'Failed to fetch student details'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/access-requests', methods=['POST'])
@require_api_key
def api_submit_access_request():
    """Submit a new access request for student data"""
    conn = None
    cur = None
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['student_id', 'requested_data', 'purpose']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        student_id = data['student_id']
        requested_data = data['requested_data']
        purpose = data['purpose']
        requester_id = request.third_party_user['user_id']
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Verify student exists
        cur.execute("SELECT user_id FROM users WHERE user_id = %s AND role = 'Student'", (student_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Student not found'}), 404
        
        # Insert access request
        cur.execute("""
            INSERT INTO access_requests (requester_id, student_id, requested_data, purpose, status, request_date)
            VALUES (%s, %s, %s, %s, 'pending', NOW())
        """, (requester_id, student_id, requested_data, purpose))
        
        request_id = cur.lastrowid
        conn.commit()
        
        return jsonify({
            'success': True,
            'request_id': request_id,
            'message': 'Access request submitted successfully'
        })
        
    except Exception as e:
        print(f"Error submitting access request: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': 'Failed to submit access request'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/access-requests', methods=['GET'])
@require_api_key
def api_get_access_requests():
    """Get all access requests for the authenticated third party user"""
    conn = None
    cur = None
    try:
        requester_id = request.third_party_user['user_id']
        
        # Get query parameters
        status = request.args.get('status')  # pending, approved, rejected
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Build query
        query = """
            SELECT 
                ar.request_id,
                ar.student_id,
                ar.requested_data,
                ar.purpose,
                ar.status,
                ar.request_date,
                ar.response_date,
                u.full_name as student_name,
                u.email as student_email
            FROM access_requests ar
            JOIN users u ON ar.student_id = u.user_id
            WHERE ar.requester_id = %s
        """
        params = [requester_id]
        
        if status:
            query += " AND ar.status = %s"
            params.append(status)
        
        query += " ORDER BY ar.request_date DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cur.execute(query, params)
        requests = cur.fetchall()
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM access_requests WHERE requester_id = %s"
        count_params = [requester_id]
        if status:
            count_query += " AND status = %s"
            count_params.append(status)
        
        cur.execute(count_query, count_params)
        total = cur.fetchone()['total']
        
        return jsonify({
            'success': True,
            'requests': requests,
            'total': total,
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        print(f"Error fetching access requests: {e}")
        return jsonify({'error': 'Failed to fetch access requests'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/access-requests/<int:request_id>', methods=['GET'])
@require_api_key
def api_get_access_request(request_id):
    """Get details of a specific access request"""
    conn = None
    cur = None
    try:
        requester_id = request.third_party_user['user_id']
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                ar.request_id,
                ar.student_id,
                ar.requested_data,
                ar.purpose,
                ar.status,
                ar.request_date,
                ar.response_date,
                u.full_name as student_name,
                u.email as student_email
            FROM access_requests ar
            JOIN users u ON ar.student_id = u.user_id
            WHERE ar.request_id = %s AND ar.requester_id = %s
        """, (request_id, requester_id))
        
        request_data = cur.fetchone()
        
        if not request_data:
            return jsonify({'error': 'Access request not found'}), 404
        
        return jsonify({
            'success': True,
            'request': request_data
        })
        
    except Exception as e:
        print(f"Error fetching access request: {e}")
        return jsonify({'error': 'Failed to fetch access request'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/approved-data/<int:student_id>', methods=['GET'])
@require_api_key
def api_get_approved_data(student_id):
    """Get approved student data for requests that have been approved"""
    conn = None
    cur = None
    try:
        requester_id = request.third_party_user['user_id']
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Check if there are approved requests for this student
        cur.execute("""
            SELECT COUNT(*) as approved_count
            FROM access_requests 
            WHERE requester_id = %s AND student_id = %s AND status = 'approved'
        """, (requester_id, student_id))
        
        approved_count = cur.fetchone()['approved_count']
        
        if approved_count == 0:
            return jsonify({'error': 'No approved requests found for this student'}), 403
        
        # Get approved student data
        cur.execute("""
            SELECT 
                u.user_id,
                u.full_name,
                u.email,
                u.student_id,
                u.department,
                pi.phone,
                pi.birth_date,
                pi.gender,
                ai.major,
                ai.year,
                ai.gpa,
                ai.advisor,
                ai.linkedin_url,
                ai.github_url,
                ci.address,
                ci.city,
                ci.state,
                ci.contact_phone
            FROM users u
            LEFT JOIN personal_information pi ON u.user_id = pi.user_id
            LEFT JOIN academic_information ai ON u.user_id = ai.user_id
            LEFT JOIN contact_information ci ON u.user_id = ci.user_id
            WHERE u.user_id = %s AND u.role = 'Student' AND u.status = 1
        """, (student_id,))
        
        student_data = cur.fetchone()
        
        if not student_data:
            return jsonify({'error': 'Student not found'}), 404
        
        # Log the data access
        cur.execute("""
            INSERT INTO access_log (user_id, resource, action, ip_address, timestamp)
            VALUES (%s, %s, 'data_access', %s, NOW())
        """, (requester_id, f"student_{student_id}", request.remote_addr))
        conn.commit()
        
        return jsonify({
            'success': True,
            'student_data': student_data,
            'approved_requests': approved_count
        })
        
    except Exception as e:
        print(f"Error fetching approved data: {e}")
        return jsonify({'error': 'Failed to fetch approved data'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/api/v1/stats', methods=['GET'])
@require_api_key
def api_get_stats():
    """Get statistics for the authenticated third party user"""
    conn = None
    cur = None
    try:
        requester_id = request.third_party_user['user_id']
        
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='abc123',
            database='ims',
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        
        # Get request statistics
        cur.execute("""
            SELECT 
                COUNT(*) as total_requests,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_requests,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_requests,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_requests
            FROM access_requests 
            WHERE requester_id = %s
        """, (requester_id,))
        
        stats = cur.fetchone()
        
        # Get recent activity (last 30 days)
        cur.execute("""
            SELECT COUNT(*) as recent_requests
            FROM access_requests 
            WHERE requester_id = %s AND request_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        """, (requester_id,))
        
        recent_stats = cur.fetchone()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_requests': stats['total_requests'] or 0,
                'pending_requests': stats['pending_requests'] or 0,
                'approved_requests': stats['approved_requests'] or 0,
                'rejected_requests': stats['rejected_requests'] or 0,
                'recent_requests_30_days': recent_stats['recent_requests'] or 0
            }
        })
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({'error': 'Failed to fetch statistics'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(debug=True)
