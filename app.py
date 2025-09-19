from flask import Flask, request, jsonify,render_template, redirect, url_for, session
from functools import wraps
import jwt
import pymysql
import hashlib
app = Flask(__name__)
app.secret_key = 'TMC'  # Use a secure random key in production!

@app.route('/')
def home():
    return render_template('login/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register/register.html')
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

        full_name = request.form.get("full_name", '').strip()
        email = request.form.get("email", '').strip()
        student_id = request.form.get("student_id", '').strip()
        password = request.form.get("password", '')
        confirm_password = request.form.get("confirm_password", '')
        
        # Validate required fields
        if not all([full_name, email, student_id, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Validate password confirmation
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Set default values for student registration
        role = "Student"
        department = "General"
        status = 1
        
        print(f"Received data: full_name={full_name}, email={email}, student_id={student_id}")
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"Password hash: {password_hash}")
        
        # Check if user already exists
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        print(f"User found: {user}")
        if user:
            return jsonify({'error': 'Email already registered'}), 409
        
        # Check if student ID already exists
        cur.execute("SELECT * FROM users WHERE student_id = %s", (student_id,))
        existing_student = cur.fetchone()
        if existing_student:
            return jsonify({'error': 'Student ID already registered'}), 409
        
        print("No existing user found, proceeding with registration")
        # Insert new user
        cur.execute("INSERT INTO users (email, password_hash, full_name, student_id, department, role, status) VALUES (%s, %s, %s, %s, %s, %s, %s)", (email, password_hash, full_name, student_id, department, role, status))
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
        return jsonify({'error': 'An error occurred during registration'}), 500

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password/forgot_password.html')
    
    try:
        email = request.form.get('email', '').strip()
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
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
            return jsonify({'error': 'Email not found'}), 404
        
        # In a real application, you would:
        # 1. Generate a secure reset token
        # 2. Store it in the database with expiration
        # 3. Send an email with the reset link
        # For now, we'll just return a success message
        
        print(f"Password reset requested for user: {user['full_name']} ({email})")
        
        return jsonify({'message': 'Password reset instructions have been sent to your email'}), 200
        
    except Exception as e:
        print(f"Error in forgot password: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
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

        # Hash the provided password to compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Look up user by email
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        print(f"User found: {user}")
        print(f"Provided password hash: {password_hash}")
        print(f"Stored password hash: {user['password_hash']}")
        if not user or user['password_hash'] != password_hash:
            return jsonify({'error': 'Invalid email or password'}), 401
        print("User authenticated successfully")
        
        session['user_id'] = user['user_id']
                
        # Create JWT token
        token = jwt.encode(
            {'id': int(user['user_id']), 'role': str(user['role'])},
            str(app.config['SECRET_KEY']),
            algorithm='HS256'
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        if user['role'] == 'Student':
            return redirect(url_for('students'))
        elif user['role'] == 'Admin':
            return redirect(url_for('admin_dashboard'))
        elif user['role'] == 'Requester':
            return redirect(url_for('requester'))
        elif user['role'] == 'Third_Party':
            return redirect(url_for('users'))
        else:
            return jsonify({'error': 'Unauthorized role'}), 403

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'error': 'An error occurred during login'}), 500

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
    roles = [
        ("", "Select Role"),
        ("admin", "Admin"),
        ("requester", "Requester"),
        ("student", "Student"),
        ("third_party", "3rd Party")
    ]

    return render_template(
        'admin/add_user.html',
        roles=roles
    )

@app.route('/users')
def users():
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='abc123',
        database='ims',
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    try:
        cur.execute("SELECT full_name, email, role, status FROM users")
        users_data = cur.fetchall()
        print(f"Fetched users: {users_data}")
    except Exception as e:
        print(f"Error fetching users: {e}")
        users_data = []
    finally:
        conn.close()

    return render_template('admin/user_management.html', users=users_data)

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin/admin.html')

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
        
        print(f"Fetched {len(recent_logs)} recent access logs and {len(incoming_requests)} incoming requests for dashboard")
        
    except Exception as e:
        print(f"Error fetching dashboard data: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return render_template('students/dashboard.html', 
                         recent_logs=recent_logs, 
                         incoming_requests=incoming_requests)

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
                ai.major,
                ai.year,
                ai.gpa,
                ai.advisor,
                ci.address,
                ci.city,
                ci.state,
                adi.emergency_contact,
                adi.relationship
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

    except Exception as e:
        print(f"Error fetching requester KPIs: {e}")
        pending_count = 0
        approved_count = 0
        rejected_count = 0
        recent_requests = []
        status_filter_home = None
        query_text = None
    finally:
        conn.close()

    return render_template(
        'requester/home.html',
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        recent_requests=recent_requests,
        active_status_home=status_filter_home or 'all',
        q=query_text or ''
    )

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
        major = request.form.get("major")
        year = request.form.get("year")
        birth_date = request.form.get("birth_date")
        gpa = request.form.get("gpa")
        advisor = request.form.get("advisor")
        address = request.form.get("address")
        city = request.form.get("city")
        state = request.form.get("state")
        emergency_contact = request.form.get("emergency_contact")
        relationship = request.form.get("relationship")
        user_id = session.get('user_id')
        print(f"Received data: email={email}, full_name={full_name}, contact_number={contact_number}, major={major}, year={year}, birth_date={birth_date}, gpa={gpa}, advisor={advisor}, address={address}, city={city}, state={state}, emergency_contact={emergency_contact}, relationship={relationship}")
        print(f"User ID from session: {user_id}")
        if not user_id:
            return redirect(url_for('login')) # Redirect to login if user_id is not set
         # Insert or update personal information
        cur.execute("""
            INSERT INTO personal_information (user_id, full_name, email, phone, birth_date) 
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            full_name = VALUES(full_name),
            email = VALUES(email),
            phone = VALUES(phone),
            birth_date = VALUES(birth_date)
        """, (user_id, full_name, email, contact_number, birth_date))
        cur.close()
        
        cur1 = conn.cursor()
        cur1.execute("""
            INSERT INTO academic_information (user_id, major, year, gpa, advisor) 
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            major = VALUES(major),
            year = VALUES(year),
            gpa = VALUES(gpa),
            advisor = VALUES(advisor)
        """, (user_id, major, year, gpa, advisor))
        cur1.close()
        
        cur2 = conn.cursor()
        cur2.execute("""
            INSERT INTO contact_information (user_id, address, city, state) 
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            address = VALUES(address),
            city = VALUES(city),
            state = VALUES(state)
        """, (user_id, address, city, state))
        cur2.close()
        
        cur3 = conn.cursor()
        cur3.execute("""
            INSERT INTO additional_information (user_id, emergency_contact, relationship) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            emergency_contact = VALUES(emergency_contact),
            relationship = VALUES(relationship)
        """, (user_id, emergency_contact, relationship))
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
        
        # Fetch students with their information from multiple tables
        cur.execute("""
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
                adi.relationship
            FROM users u
            LEFT JOIN personal_information pi ON u.user_id = pi.user_id
            LEFT JOIN academic_information ai ON u.user_id = ai.user_id
            LEFT JOIN contact_information ci ON u.user_id = ci.user_id
            LEFT JOIN additional_information adi ON u.user_id = adi.user_id
            WHERE u.role = 'Student'
            ORDER BY u.full_name
        """)
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

    return render_template('requester/view_student.html', students=students_data)

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
                SELECT address, city, state, phone
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
            return jsonify({'error': 'Please select at least one data point'}), 400
        
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
        return jsonify({'error': 'Error submitting access request'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(debug=True)
