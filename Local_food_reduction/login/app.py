from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify
from flask_bcrypt import Bcrypt
import sqlite3
import re
import os
import functools
import random
import string
import requests

app = Flask(__name__)
bcrypt = Bcrypt(app)

# ========================= CONFIGURATION ============================
app.secret_key = 'your_secret_key'
app.config['SESSION_PERMANENT'] = False

# SQLite Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_DB_PATH = os.path.join(BASE_DIR, "food_details.db")

# ===================== SQLITE UTILITIES =============================
def get_sqlite_connection():
    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"SQLite Error: {e}")
        return None

def init_sqlite_db():
    with get_sqlite_connection() as conn:
        if conn:
            cursor = conn.cursor()
            cursor.executescript('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT DEFAULT 'user',
                    last_login TEXT
                );
                
                CREATE TABLE IF NOT EXISTS food_donations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    food_name TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    expiry_date TEXT NOT NULL,
                    location TEXT NOT NULL,
                    latitude REAL,
                    longitude REAL,
                    status TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES accounts(id)
                );
                
                CREATE TABLE IF NOT EXISTS food_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    request_details TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    pickup_code TEXT,
                    address TEXT,
                    FOREIGN KEY (user_id) REFERENCES accounts(id)
                );
                
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES accounts(id)
                );
                
                CREATE TABLE IF NOT EXISTS food_waste (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_name TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    expiry_date TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES accounts(id)
                );

                CREATE TABLE IF NOT EXISTS otp_verification (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    otp_code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            conn.commit()

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('loggedin'):
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view

# Removed donor_required decorator as donor role is removed

def user_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('loggedin'):
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        if session.get('role') != 'user':
            flash("User access required.", "danger")
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view

# ======================= GENERAL ROUTES =============================
@app.route('/')
def home():
    return render_template('index.html')


@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    user_message = data.get("message", "").lower()

    if any(greet in user_message for greet in ["hi", "hello", "hey"]):
        reply = "Hello! How can I assist you today?"
    elif any(phrase in user_message for phrase in ["don't have account", "no account", "not registered"]):
        reply = "No worries! Just click on 'Register' in the top menu and fill out the form to create your account."
    elif "forgot password" in user_message:
        reply = "Click 'Login', then choose 'Forgot Password' to reset it."
    elif any(phrase in user_message for phrase in ["change email", "change username"]):
        reply = "You can update your email or username in your profile settings."
    elif "delete account" in user_message:
        reply = "Go to your profile and click on 'Delete Account' at the bottom."
    elif "donate" in user_message:
        reply = "To donate food, click 'Donate Food', fill in the details and submit the form."
    elif any(phrase in user_message for phrase in ["how it works", "how does this work"]):
        reply = "We connect people who want to donate extra food with those who need it."
    elif any(phrase in user_message for phrase in ["list food", "add food"]):
        reply = "Click on 'Donate Food', fill in the info about your food, and submit."
    elif any(phrase in user_message for phrase in ["claim food", "take food", "get food", "receive food", "how can i get food", "request"]):
        reply = "To get food, click on 'Request Food', browse the listings, and select what you need."
    elif "schedule pickup" in user_message:
        reply = "You can schedule a pickup during the donation form process if that option is available."
    elif any(phrase in user_message for phrase in ["after submit", "what next"]):
        reply = "Once submitted, your food listing will be visible to receivers who can claim it."
    elif any(phrase in user_message for phrase in ["food limit", "how much food"]):
        reply = "You can donate any amount, just ensure it's safe and not spoiled."
    elif any(phrase in user_message for phrase in ["received", "confirmed"]):
        reply = "You’ll be notified once someone claims and confirms receiving the food."
    elif any(phrase in user_message for phrase in ["edit donation", "cancel donation"]):
        reply = "Visit your profile and click 'Edit' or 'Cancel' next to your donation."
    elif "food safe" in user_message:
        reply = "We encourage all donors to share only fresh, edible food. Check listings before requesting."
    elif "specific food" in user_message:
        reply = "Yes, you can filter listings or request specific types on the 'Request Food' page."
    elif any(phrase in user_message for phrase in ["didn't get food", "not received"]):
        reply = "Please contact the platform support if you have issues receiving claimed food."
    elif "deliver myself" in user_message:
        reply = "If you're donating, yes, you usually need to deliver it unless agreed otherwise."
    elif "delivery" in user_message:
        reply = "Some organizations on the platform may help with delivery. Check with them directly."
    elif "transportation" in user_message:
        reply = "Transportation is usually managed by the donor or a volunteer—details will be shown on the listing."
    elif any(phrase in user_message for phrase in ["what food allowed", "food guidelines"]):
        reply = "Only donate safe, fresh food. No expired or spoiled items, please."
    elif "spoiled food" in user_message:
        reply = "Please report spoiled food through the Contact page so we can follow up."
    elif "liability" in user_message:
        reply = "We encourage donors and receivers to communicate clearly. The platform provides guidance but isn't liable for individual exchanges."
    elif any(phrase in user_message for phrase in ["reduce food waste", "impact"]):
        reply = "By donating and claiming food, you’re reducing waste and helping feed people in need."
    elif any(phrase in user_message for phrase in ["stats", "how much donated"]):
        reply = "You can view your donation stats in your profile dashboard."
    elif any(phrase in user_message for phrase in ["ecowaste ai", "what can you do"]):
        reply = "I’m EcoWaste AI! I can help you donate, request food, manage your account, and answer common questions."
    elif "talk to human" in user_message:
        reply = "You can reach our support team through the Contact page."
    elif "available" in user_message:
        reply = "Click 'View Available Food' to see what's available."
    elif any(phrase in user_message for phrase in ["register", "sign up"]):
        reply = "Click 'Register' on the navbar and complete the form."
    elif any(phrase in user_message for phrase in ["login", "log in"]):
        reply = "Click 'Login' and enter your credentials."
    elif "about" in user_message:
        reply = "This platform connects food donors with recipients to reduce waste and hunger."
    elif "contact" in user_message:
        reply = "Visit the 'Contact' page to reach us."
    elif "profile" in user_message:
        reply = "Your profile shows your donations, requests, and settings."
    elif any(phrase in user_message for phrase in ["food waste", "why"]):
        reply = "We reduce food waste by redistributing it to people in need."

    # ✅ PURPOSE-RELATED & GENERAL QUESTIONS
    elif any(phrase in user_message for phrase in ["why was this platform created", "why did you create this", "what is the purpose", "goal of this platform", "aim of the platform", "reason for platform"]):
        reply = "This platform was created to reduce food waste and help people in need by connecting food donors with recipients."
    elif any(phrase in user_message for phrase in ["mission", "vision", "what do you stand for"]):
        reply = "Our mission is to minimize food waste and fight hunger by creating a community-driven food sharing network."
    elif any(phrase in user_message for phrase in ["who made this", "who created this", "who developed this"]):
        reply = "This platform was developed by a team passionate about sustainability, food equity, and reducing waste."
    elif any(phrase in user_message for phrase in ["how do you reduce food waste", "how does it help with food waste"]):
        reply = "We reduce food waste by allowing individuals and businesses to donate surplus food to those who need it."

    # ✅ NEW USER COMMON QUESTIONS
    elif any(phrase in user_message for phrase in ["is it free", "do i have to pay", "cost to use", "does it cost anything"]):
        reply = "Yes, it's completely free to use! Donating and receiving food on the platform doesn't cost anything."
    elif any(phrase in user_message for phrase in ["who can join", "who is eligible", "who can use this"]):
        reply = "Anyone can join—whether you're looking to donate extra food or in need of food support."
    elif any(phrase in user_message for phrase in ["where does the food come from", "who donates", "source of food"]):
        reply = "The food comes from individuals, households, restaurants, and organizations willing to share surplus food."
    elif any(phrase in user_message for phrase in ["available in my area", "my city", "is this in", "location based"]):
        reply = "We're expanding! Please check the homepage or contact support to confirm availability in your area."
    elif any(phrase in user_message for phrase in ["volunteer", "help the platform", "how can i help"]):
        reply = "We’d love your help! Visit the 'Volunteer' section or Contact page to sign up and support our mission."

    else:
        reply = "I can help with donating, requesting, registering, safety tips, and more. Try asking in a different way!"

    return jsonify({"reply": reply})


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('loggedin'):
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_requests'))
    elif role == 'user':
        return redirect(url_for('user_dashboard'))
    else:
        flash('Invalid user role.', 'danger')
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if not session.get('loggedin'):
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))

    user_id = session['id']

    with get_sqlite_connection() as conn:
        cursor = conn.cursor()

        # Fetch user email
        cursor.execute("SELECT email FROM accounts WHERE id = ?", (user_id,))
        user_email_row = cursor.fetchone()
        user_email = user_email_row['email'] if user_email_row else 'N/A'

        # Total donations by user
        cursor.execute("SELECT COUNT(*) AS count FROM food_donations WHERE user_id = ?", (user_id,))
        total_donations = cursor.fetchone()['count']

        # Pending requests by user
        cursor.execute("SELECT COUNT(*) AS count FROM food_requests WHERE user_id = ? AND status = 'Pending'", (user_id,))
        pending_requests = cursor.fetchone()['count']

        # Total requests by user
        cursor.execute("SELECT COUNT(*) AS count FROM food_requests WHERE user_id = ?", (user_id,))
        total_requests = cursor.fetchone()['count']

        # Recent activity: donations and requests
        cursor.execute('''
            SELECT 'Donation' AS type, food_name AS details, expiry_date AS date
            FROM food_donations
            WHERE user_id = ?
            UNION ALL
            SELECT 'Request' AS type, request_details AS details, created_at AS date
            FROM food_requests
            WHERE user_id = ?
            ORDER BY date DESC
            LIMIT 10
        ''', (user_id, user_id))
        recent_activity = cursor.fetchall()

        # Fetch unread notifications for the user
        cursor.execute('''
            SELECT id, message, created_at
            FROM notifications
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
        ''', (user_id,))
        notifications = cursor.fetchall()

    return render_template('profile.html',
                           total_donations=total_donations,
                           pending_requests=pending_requests,
                           total_requests=total_requests,
                           recent_activity=recent_activity,
                           user_email=user_email,
                           notifications=notifications)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('loggedin'):
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))

    msg = ''
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not current_password or not new_password or not confirm_password:
            msg = 'Please fill all fields!'
        elif new_password != confirm_password:
            msg = 'New password and confirm password do not match!'
        else:
            user_id = session['id']
            with get_sqlite_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM accounts WHERE id = ?", (user_id,))
                user = cursor.fetchone()
                if user and bcrypt.check_password_hash(user['password'], current_password):
                    hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    cursor.execute("UPDATE accounts SET password = ? WHERE id = ?", (hashed, user_id))
                    conn.commit()
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('profile'))
                else:
                    msg = 'Current password is incorrect!'

    return render_template('change_password.html', msg=msg)

# ===================== AUTH ROUTES ================================
def validate_email_api(email):
    # Using Abstract API Email Validation as example
    # You need to get your API key from https://www.abstractapi.com/email-verification-validation-api
    API_KEY = 'your_abstractapi_key'  # Replace with your actual API key
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={API_KEY}&email={email}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            # Check if email is deliverable and not disposable
            if data.get('deliverability') == 'DELIVERABLE' and not data.get('is_disposable_email', True):
                return True
            else:
                return False
        else:
            print(f"Email validation API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"Exception during email validation API call: {e}")
        return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            email = request.form.get('email', '').strip()
            role = request.form.get('role', 'user').strip().lower()
            if role not in ['user', 'admin']:
                role = 'user'

            # Input validation
            if not name or not password or not email or not confirm_password:
                msg = 'Please fill all fields!'
            elif len(name) < 4:
                msg = 'Name must be at least 4 characters!'
            elif len(password) < 6:
                msg = 'Password must be at least 6 characters!'
            elif password != confirm_password:
                msg = 'Password and confirm password do not match!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            # Removed email validation API call
            else:
                with get_sqlite_connection() as conn:
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT * FROM accounts WHERE email = ?', (email,))
                        account = cursor.fetchone()

                        if account:
                            msg = 'Account already exists!'
                        else:
                            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
                            cursor.execute('''
                                INSERT INTO accounts (username, password, email, role, last_login) 
                                VALUES (?, ?, ?, ?, datetime('now'))
                            ''', (name, hashed, email, role))
                            conn.commit()

                            flash('Registration successful! You can now login.', 'success')
                            return redirect(url_for('login'))
                    else:
                        msg = 'Database connection error!'
        except Exception as e:
            print(f"Registration error: {e}")
            msg = 'An error occurred during registration'

    return render_template('register.html', msg=msg)

from flask_mail import Mail, Message
import secrets

# Update the mail configuration with a commonly used SMTP server example (Gmail SMTP)
# You must replace these with your actual email credentials and allow less secure apps or app password if using Gmail

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_gmail_address@gmail.com'  # Replace with your Gmail address
app.config['MAIL_PASSWORD'] = 'your_gmail_app_password'  # Replace with your Gmail app password or email password

mail = Mail(app)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()

            if not email or not password:
                msg = 'Please fill all fields!'
            else:
                with get_sqlite_connection() as conn:
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT * FROM accounts WHERE email = ?', (email,))
                        account = cursor.fetchone()

                        if account and bcrypt.check_password_hash(account['password'], password):
                            session['loggedin'] = True
                            session['id'] = account['id']
                            session['username'] = account['username']
                            session['role'] = account['role']
                            
                            # Debug print to verify role
                            print(f"User logged in with role: {account['role']}")
                            
                            # Update last login time
                            cursor.execute('UPDATE accounts SET last_login = datetime("now") WHERE id = ?', (account['id'],))
                            conn.commit()
                            
                            flash('Logged in successfully!', 'success')
                            if account['role'] == 'user':
                                return redirect(url_for('home'))
                            else:
                                return redirect(url_for('dashboard'))
                        else:
                            msg = 'Invalid email or password!'
                    else:
                        msg = 'Database connection error!'
        except Exception as e:
            print(f"Login error: {e}")
            msg = 'An error occurred during login'

    return render_template('login.html', msg=msg)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    msg = ''
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            msg = 'Please enter your email address.'
        else:
            with get_sqlite_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM accounts WHERE email = ?', (email,))
                user = cursor.fetchone()
                if user:
                    # Generate OTP
                    otp_code = secrets.token_hex(3)  # 6 hex digits
                    # Store OTP in otp_verification table
                    cursor.execute('INSERT INTO otp_verification (email, otp_code) VALUES (?, ?)', (email, otp_code))
                    conn.commit()
                    # Send OTP via email
                    try:
                        msg_email = Message('Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
                        msg_email.body = f'Your OTP for password reset is: {otp_code}'
                        mail.send(msg_email)
                        msg = 'An OTP has been sent to your email.'
                    except Exception as e:
                        print(f"Email send error: {e}")
                        msg = 'Failed to send OTP email. Please try again later.'
                else:
                    msg = 'Email not found in our records.'
    return render_template('forgot_password.html', message=msg)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# ===================== FOOD DONATIONS =========================
@app.route('/food_list')
def food_list():
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM food_donations')
        foods = cursor.fetchall()
    return render_template('food_list.html', foods=foods)

@app.route('/request_food/<int:food_id>', methods=['GET', 'POST'])
def request_food(food_id):
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM food_donations WHERE id = ?", (food_id,))
        food = cursor.fetchone()

        if request.method == 'POST':
            # Check if food is available and not expired or picked up
            if food['status'] != 'Available':
                flash("This food item is not available for request.", "danger")
                return redirect(url_for('food_list'))

            user_id = session['id']
            request_details = f"Requested food item ID: {food_id}"
            status = 'Pending'
            address = request.form.get('address', '').strip()

            cursor.execute("INSERT INTO food_requests (user_id, request_details, status, address) VALUES (?, ?, ?, ?)",
                           (user_id, request_details, status, address))
            conn.commit()
            flash("Request submitted for admin approval.", "success")
            return redirect(url_for('food_list'))

    return render_template('food_details.html', food=food)

@app.route('/add_food_request_from_detail/<int:food_id>', methods=['POST'])
def add_food_request_from_detail(food_id):
    if not session.get('id'):
        flash("Please login to request food.", "warning")
        return redirect(url_for('login'))

    user_id = session['id']
    request_details = f"Requesting food: ID {food_id}"
    status = 'Pending'

    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO food_requests (user_id, request_details, status) VALUES (?, ?, ?)",
                       (user_id, request_details, status))
        conn.commit()
    flash("Food request submitted successfully!", "success")
    return redirect(url_for('requests'))


@app.route('/add_food', methods=['GET', 'POST'])
@user_required
def add_food():
    print(f"add_food called with method: {request.method}, session: {dict(session)}")
    if request.method == 'POST':
        if not session.get('id'):
            flash("Please login first!", "warning")
            return redirect(url_for('login'))

        food_name = request.form.get('food_name')
        quantity = request.form.get('quantity')
        expiry_date = request.form.get('expiry_date')
        location = request.form.get('location')
        status = request.form.get('status')
        user_id = session['id']

        print(f"Received form data: food_name={food_name}, quantity={quantity}, expiry_date={expiry_date}, location={location}, status={status}, user_id={user_id}")

        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO food_donations (food_name, quantity, expiry_date, location, status, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (food_name, quantity, expiry_date, location, status, user_id))
            conn.commit()
        flash('Food donation added!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('add_food.html')

# Removed duplicate user_dashboard route that only fetched donations

# Remove the first duplicate user_dashboard route function entirely

# The below user_dashboard route is the intended one to keep
# Removed the first duplicate user_dashboard route function entirely


@app.route('/delete_food/<int:food_id>', methods=['POST'])
def delete_food(food_id):
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM food_donations WHERE id=?", (food_id,))
        conn.commit()
    flash("Food donation deleted.", "info")
    return redirect(url_for('food_list'))

# ---------------- Update Fields (Dynamic Handler) --------------------
def update_field_template(field_name, food_id):
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            new_value = request.form[field_name]
            cursor.execute(f"UPDATE food_donations SET {field_name} = ? WHERE id = ?", (new_value, food_id))
            conn.commit()
            return redirect(url_for('food_list'))

        cursor.execute("SELECT * FROM food_donations WHERE id=?", (food_id,))
        food = cursor.fetchone()
    return render_template('update_field.html', field=field_name, food=food)

@app.route('/update_food_name/<int:food_id>', methods=['GET', 'POST'])
def update_food_name(food_id):
    return update_field_template('food_name', food_id)

@app.route('/update_quantity/<int:food_id>', methods=['GET', 'POST'])
def update_quantity(food_id):
    return update_field_template('quantity', food_id)

@app.route('/update_location/<int:food_id>', methods=['GET', 'POST'])
def update_location(food_id):
    return update_field_template('location', food_id)

@app.route('/update_status/<int:food_id>', methods=['GET', 'POST'])
def update_status(food_id):
    return update_field_template('status', food_id)

# ====================== FOOD REQUESTS ========================
@app.route('/update_request_address/<int:req_id>', methods=['POST'])
def update_request_address(req_id):
    if not session.get('id'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    address = request.form.get('address', '').strip()
    if address:
        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE food_requests SET address = ? WHERE id = ?", (address, req_id))
            conn.commit()
        flash("Address updated successfully!", "success")
    return redirect(url_for('requests'))

@app.route('/requests', methods=['GET', 'POST'])
def requests():
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        # Fetch requests for the logged-in user with food details and donor info
        cursor.execute('''
            SELECT r.id, r.request_details, r.status, r.pickup_code, r.created_at, r.address,
                   fd.food_name, fd.location,
                   a.username as donor_username
            FROM food_requests r
            JOIN food_donations fd ON fd.id = (
                SELECT CAST(SUBSTR(r.request_details, INSTR(r.request_details, 'ID ') + 3) AS INTEGER)
            )
            JOIN accounts a ON fd.user_id = a.id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        ''', (session['id'],))
        reqs = cursor.fetchall()

        # Fetch unread notifications for the user
        cursor.execute('''
            SELECT id, message, created_at
            FROM notifications
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
        ''', (session['id'],))
        notifications = cursor.fetchall()

    return render_template('requests.html', requests=reqs, notifications=notifications)

@app.route('/add_request', methods=['GET', 'POST'])
def add_request():
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['id']
        request_details = request.form['request_details']
        status = request.form['status']

        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO food_requests (user_id, request_details, status) VALUES (?, ?, ?)",
                           (user_id, request_details, status))
            conn.commit()
        flash("Food request submitted!", "success")
        return redirect(url_for('requests'))

    return render_template('add_request.html')

# ===================== FEEDBACK ===========================
@app.route('/feedback')
def feedback():
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM feedback")
        all_feedback = cursor.fetchall()
    return render_template('feedback.html', feedback=all_feedback)

@app.route('/submit_feedback', methods=['GET', 'POST'])
def submit_feedback():
    if request.method == 'POST':
        if not session.get('id'):
            flash("Please login first!", "warning")
            return redirect(url_for('login'))

        user_id = session['id']
        message = request.form['message']
        rating = request.form.get('rating', None)

        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO feedback (user_id, message) VALUES (?, ?)", (user_id, message))
            # Optionally, you can store rating in a separate column if added to feedback table
            conn.commit()
        flash("Thank you for your feedback!", "success")
        return redirect(url_for('feedback'))

    return render_template('submit_feedback.html')

# ===================== FOOD WASTE TRACKING ===================
@app.route('/food_waste')
def food_waste():
    with get_sqlite_connection() as conn:
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM food_waste")
            data = cursor.fetchall()
            return render_template('food_waste.html', food_waste=data)
        flash("SQLite database connection failed.", "danger")
        return redirect(url_for('food_list'))

@app.route('/add_food_waste', methods=['GET', 'POST'])
def add_food_waste():
    if request.method == 'POST':
        item_name = request.form['item_name']
        quantity = request.form['quantity']
        expiry_date = request.form['expiry_date']

        with get_sqlite_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO food_waste (item_name, quantity, expiry_date)
                    VALUES (?, ?, ?)
                ''', (item_name, quantity, expiry_date))
                conn.commit()
                flash("Food waste record added!", "success")
                return redirect(url_for('food_waste'))

    return render_template('add_food_waste.html')

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('loggedin'):
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view

@app.route('/admin/requests')
@admin_required
def admin_requests():
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM food_requests")
        requests_data = cursor.fetchall()
        cursor.execute("SELECT id, username, email, last_login FROM accounts WHERE role = 'donor'")
        donors = cursor.fetchall()
    return render_template('admin_dashboard.html', requests=requests_data, donors=donors)

@app.route('/user_dashboard')
@user_required
def user_dashboard():
    user_id = session.get('id')
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        # Fetch available food donations with donor info
        cursor.execute('''
            SELECT fd.*, a.username as donor_username
            FROM food_donations fd
            JOIN accounts a ON fd.user_id = a.id
            WHERE fd.status = 'Available'
        ''')
        foods = cursor.fetchall()

        # Fetch user's food requests with details
        cursor.execute('''
            SELECT r.*
            FROM food_requests r
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        ''', (user_id,))
        requests_data = cursor.fetchall()

        # Fetch unread notifications for the user
        cursor.execute('''
            SELECT id, message, created_at
            FROM notifications
            WHERE user_id = ? AND is_read = 0
            ORDER BY created_at DESC
        ''', (user_id,))
        notifications = cursor.fetchall()

    return render_template('user_dashboard.html', foods=foods, requests=requests_data, notifications=notifications)

@app.route('/admin/approve_request/<int:req_id>')
@admin_required
def approve_request(req_id):
    pickup_code = ''.join(random.choices(string.digits, k=6))
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE food_requests SET status='Approved', pickup_code=? WHERE id=?", (pickup_code, req_id))
        conn.commit()

        # Fetch user email and id for the request
        cursor.execute('''
            SELECT a.email, a.username, a.id as user_id
            FROM food_requests r
            JOIN accounts a ON r.user_id = a.id
            WHERE r.id = ?
        ''', (req_id,))
        user_info = cursor.fetchone()

        # Insert notification for the user
        if user_info:
            user_id = user_info['user_id']
            notification_message = f"Your food request has been approved. Your pickup code is: {pickup_code}."
            cursor.execute('''
                INSERT INTO notifications (user_id, message, is_read)
                VALUES (?, ?, 0)
            ''', (user_id, notification_message))
            conn.commit()

    if user_info:
        user_email = user_info['email']
        user_name = user_info['username']
        try:
            msg = Message('Food Request Approved',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[user_email])
            msg.body = f"Hello {user_name},\n\nYour food request has been approved. Your pickup code is: {pickup_code}.\n\nThank you for using our service."
            mail.send(msg)
        except Exception as e:
            print(f"Error sending approval email: {e}")

    flash(f"Request approved. Pickup code: {pickup_code}", "success")
    return redirect(url_for('admin_requests'))

@app.route('/admin/reject_request/<int:req_id>')
@admin_required
def reject_request(req_id):
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE food_requests SET status='Rejected' WHERE id=?", (req_id,))
        conn.commit()
    flash("Request rejected.", "danger")
    return redirect(url_for('admin_requests'))

@app.route('/confirm_pickup/<int:req_id>', methods=['GET', 'POST'])
def confirm_pickup(req_id):
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        # Update request status to 'Picked Up'
        cursor.execute("UPDATE food_requests SET status = 'Picked Up' WHERE id = ?", (req_id,))

        # Find the food_id from request_details
        cursor.execute("SELECT request_details FROM food_requests WHERE id = ?", (req_id,))
        row = cursor.fetchone()
        food_id = None
        if row:
            import re
            match = re.search(r'ID:?\s*(\d+)', row['request_details'])
            if match:
                food_id = int(match.group(1))

        # Delete the food donation item if found
        if food_id:
            cursor.execute("DELETE FROM food_donations WHERE id = ?", (food_id,))

        conn.commit()

    flash("Pickup confirmed and food item removed from list. Thank you!", "success")
    return redirect(url_for('requests'))

@app.route('/submit_feedback_request/<int:req_id>', methods=['GET', 'POST'])
def submit_feedback_request(req_id):
    if not session.get('loggedin'):
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        feedback_message = request.form.get('message', '').strip()
        if feedback_message:
            user_id = session['id']
            with get_sqlite_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO feedback (user_id, message) VALUES (?, ?)", (user_id, feedback_message))
                conn.commit()
            flash("Thank you for your feedback!", "success")
            return redirect(url_for('requests'))
        else:
            flash("Please enter feedback message.", "warning")

    return render_template('submit_feedback.html', req_id=req_id)

if __name__ == '__main__':
    init_sqlite_db()
    print("Server running at http://127.0.0.1:5000")
    app.run(debug=True)
