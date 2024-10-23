from flask import Flask, request, jsonify, make_response, session, redirect, url_for, render_template
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event, text
from flask_wtf.csrf import CSRFProtect
import jwt
import datetime
from functools import wraps
import os
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import bleach
from datetime import timezone
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, HiddenField
from wtforms.validators import InputRequired, Length, Regexp, NumberRange

app = Flask(__name__)

# Enhanced Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)  # 256-bit random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'bank.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token expiry
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['WTF_CSRF_ENABLED'] = False  # Temporarily disable CSRF for testing
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None


csrf = CSRFProtect(app)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers.pop('Content-Security-Policy', None)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# Enhanced cookie security
def set_secure_cookie(response, key, value, max_age=1800):
    response.set_cookie(
        key,
        value,
        max_age=max_age,
        httponly=False,
        secure=False,
        samesite=None,
        path='/'
    )
    return response

# Session management
@app.before_request
def session_management():
    if 'last_active' in session:
        # Check for session timeout
        last_active = datetime.datetime.fromisoformat(session['last_active'])
        if (datetime.datetime.utcnow() - last_active) > datetime.timedelta(minutes=30):
            session.clear()
            return redirect(url_for('login'))

    session['last_active'] = datetime.datetime.utcnow().isoformat()

# Token blacklist for logged out tokens
token_blacklist = set()

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/bank.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Bank application startup')

# Rate Limiting Configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

db = SQLAlchemy(app)

# Enhanced Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    account_locked_until = db.Column(db.DateTime)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))

# SQL Injection Protection
@event.listens_for(User.__table__, 'after_create')
def create_user_triggers(target, connection, **kw):
    connection.execute(text("""
        CREATE TRIGGER IF NOT EXISTS prevent_balance_manipulation
        BEFORE UPDATE ON users
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN NEW.balance < 0 THEN
                    RAISE(ABORT, 'Balance cannot be negative')
            END;
        END;
    """))

def init_db():
    # Delete the database file if it exists
    db_path = os.path.join(app.instance_path, 'bank.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        app.logger.info(f"Removed existing database at {db_path}")

    # Create the instance folder if it doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    # Create all tables
    with app.app_context():
        db.drop_all()  # Drop any existing tables
        db.create_all()  # Create all tables fresh
        app.logger.info("Database tables created successfully!")

# Initialize database tables
with app.app_context():
    try:
        # Try to query the User table to check if it needs updating
        User.query.first()
    except Exception as e:
        app.logger.info("Database needs initialization")
        init_db()

class RegistrationForm(FlaskForm):
    csrf_token = HiddenField()
    username = StringField('Username', validators=[
        InputRequired(),
        Length(min=4, max=25),
        Regexp('^[a-zA-Z0-9_.-]+$', message='Invalid username format')
    ])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=8)
    ])

class LoginForm(FlaskForm):
    csrf_token = HiddenField()
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class TransactionForm(FlaskForm):
    csrf_token = HiddenField()
    action = HiddenField('Action', validators=[InputRequired()])
    amount = FloatField('Amount', validators=[
        InputRequired(),
        NumberRange(min=0.01, max=10000, message='Amount must be between $0.01 and $10,000')
    ])

class EmptyForm(FlaskForm):
    pass

# Security Middleware
@app.before_request
def security_checks():
    # # Allow localhost testing
    # if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
    #     return None
    #
    # # Rest of your security checks...
    # blocked_ranges = ["1.0.", "192.168."]
    # if any(request.remote_addr.startswith(ip) for ip in blocked_ranges):
    #     app.logger.warning(f'Blocked request from suspicious IP: {request.remote_addr}')
    #     return "Access denied", 403
    #
    # # Check for common attack patterns in URL
    # suspicious_patterns = [
    #     r'\.\./', r'%2e%2e%2f', r'exec\(', r'eval\(',
    #     r'union\s+select', r'concat\(', r'information_schema'
    # ]
    # url = request.url.lower()
    # if any(re.search(pattern, url) for pattern in suspicious_patterns):
    #     app.logger.warning(f'Suspicious URL pattern detected: {url}')
    #     return "Invalid request", 400
    return None

# Enhanced Token Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')

        if not token:
            return redirect(url_for('login'))

        if token in token_blacklist:
            return redirect(url_for('login'))

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            # Verify token IP matches current request
            if data.get('ip') != request.remote_addr:
                raise jwt.InvalidTokenError('IP mismatch')

            # Check token expiration
            exp = datetime.datetime.fromtimestamp(data['exp'], tz=timezone.utc)
            if datetime.datetime.now(timezone.utc) > exp:
                return redirect(url_for('login'))

            current_user = User.query.filter_by(name=data['user']).first()
            if not current_user:
                return redirect(url_for('login'))

        except jwt.InvalidTokenError:
            app.logger.warning(f'Invalid token attempt from IP: {request.remote_addr}')
            return redirect(url_for('login'))

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("25 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = bleach.clean(form.username.data)
        password = form.password.data

        if not user or not password:
            return jsonify({'error': 'Username and password required'}), 400

        # Enhanced password validation
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        if not re.match(r'^[a-zA-Z0-9_.-]+$', user):
            return jsonify({'error': 'Invalid username format'}), 400

        if User.query.filter_by(name=user).first():
            return jsonify({'error': 'Username already exists'}), 400

        new_user = User(
            name=user,
            password=generate_password_hash(password, method='pbkdf2:sha256:600000'),
            balance=0.0
        )

        db.session.add(new_user)
        db.session.commit()

        app.logger.info(f'New user registered: {user} from IP: {request.remote_addr}')
        return redirect(url_for('login')), 302
    elif request.method == 'POST':
        return jsonify({'error': 'Invalid form submission'}), 400

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("25 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = bleach.clean(form.username.data)
        password = form.password.data

        # Enhanced logging for potential attacks
        app.logger.info(f'Login attempt for user: {user} from IP: {request.remote_addr} User-Agent: {request.headers.get("User-Agent")}')

        if not user or not password:
            return jsonify({'error': 'Username and password required'}), 401

        user_record = User.query.filter_by(name=user).first()

        # Check for brute force attempts from IP
        ip_key = f"login_attempts_{request.remote_addr}"
        ip_attempts = session.get(ip_key, 0)
        if ip_attempts >= 10:  # IP-based rate limiting
            app.logger.warning(f'IP address blocked due to too many attempts: {request.remote_addr}')
            return jsonify({'error': 'Too many login attempts from this IP'}), 429

        # Check if account is locked
        if user_record and user_record.account_locked_until:
            if datetime.datetime.utcnow() < user_record.account_locked_until:
                return jsonify({'error': 'Account is temporarily locked'}), 401
            else:
                user_record.failed_login_attempts = 0
                user_record.account_locked_until = None

        if not user_record or not check_password_hash(user_record.password, password):
            session[ip_key] = ip_attempts + 1
            if user_record:
                user_record.failed_login_attempts += 1
                user_record.last_login_attempt = datetime.datetime.utcnow()

                # Lock account after 5 failed attempts
                if user_record.failed_login_attempts >= 5:
                    lock_duration = datetime.timedelta(minutes=15)
                    user_record.account_locked_until = datetime.datetime.utcnow() + lock_duration
                db.session.commit()

            app.logger.warning(f'Failed login attempt for user: {user} from IP: {request.remote_addr}')
            return jsonify({'error': 'Invalid username or password'}), 401

        # Reset failed attempts on successful login
        user_record.failed_login_attempts = 0
        user_record.last_login_attempt = datetime.datetime.utcnow()
        session[ip_key] = 0  # Reset IP-based counter
        db.session.commit()

        # Generate JWT token with enhanced security
        token = jwt.encode({
            'user': user_record.name,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'jti': secrets.token_hex(16),
            'ip': request.remote_addr  # Bind token to IP
        }, app.config['SECRET_KEY'], algorithm="HS256")

        response = make_response(redirect(url_for('dashboard')))
        set_secure_cookie(response, 'token', token)
        app.logger.info(f'Successful login for user: {user} from IP: {request.remote_addr}')
        return response
    elif request.method == 'POST':
        return jsonify({'error': 'Invalid form submission'}), 400

    return render_template('login.html', form=form)

@app.route('/')
@token_required
def dashboard(current_user):
    # form = EmptyForm()
    transactions = Transaction.query.filter_by(user_id=current_user.id) \
        .order_by(Transaction.timestamp.desc()) \
        .limit(10).all()
    return render_template('dashboard.html',
                         username=escape(current_user.name),
                         balance=current_user.balance,
                         transactions=transactions)

@app.route('/manage', methods=['POST'])
@token_required
@limiter.limit("30 per minute")
def manage(current_user):
    form = TransactionForm()
    if form.validate_on_submit():
        action = bleach.clean(form.action.data)
        amount = form.amount.data

        if not action or not amount:
            return jsonify({'error': 'Action and amount required'}), 400

        try:
            amount = float(amount)
            if not (0 < amount <= 10000):  # Reasonable transaction limit
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Invalid amount'}), 400

        # Transaction handling with proper error checking
        try:
            if action == 'withdraw':
                if current_user.balance < amount:
                    return jsonify({'error': 'Insufficient funds'}), 400
                current_user.balance -= amount
            elif action == 'deposit':
                current_user.balance += amount
            else:
                return jsonify({'error': 'Invalid action'}), 400

            # Record transaction
            transaction = Transaction(
                user_id=current_user.id,
                type=action,
                amount=amount,
                ip_address=request.remote_addr
            )
            db.session.add(transaction)
            db.session.commit()

            app.logger.info(f'Successful {action} of {amount} for user: {current_user.name}')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Transaction failed: {str(e)}')
            return jsonify({'error': 'Invalid transaction data'}), 400
    else:
        return jsonify({'error': 'Invalid form submission'}), 400

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    token = request.cookies.get('token')
    if token:
        token_blacklist.add(token)  # Add token to blacklist
    response.delete_cookie('token', path='/', domain=request.host.split(':')[0])
    session.clear()
    return response

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    # For testing purposes, run without SSL on port 5000
    # Remember to switch back to SSL and secure settings in production
    app.run(host='127.0.0.1', port=5000, debug=False)
