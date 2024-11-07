from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
import re
import secrets
import bleach
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'bank.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,  # Maximum number of database connections in the pool
    'max_overflow': 20,  # Maximum number of connections that can be created beyond pool_size
    'pool_timeout': 30,  # Timeout for getting a connection from the pool
    'pool_recycle': 1800,  # Recycle connections after 30 minutes
}

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Ensure instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Database setup
db = SQLAlchemy(app)

# Models remain the same as in original code
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))

# Create tables
with app.app_context():
    db.create_all()

# Helper functions remain the same
def get_user_from_cookie(request):
    cookie = request.cookies.get('session')
    if not cookie:
        return None
    try:
        user = User.query.filter_by(name=cookie).first()
        if user:
            return user
    except:
        return None
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_user_from_cookie(request)
        if not user:
            return jsonify({'error': 'Please login first'}), 401
        return f(user, *args, **kwargs)
    return decorated

# Modified registration endpoint with rate limiting
@app.route('/register')
@app.route('/register.php')
@limiter.limit("3 per minute", error_message="Too many registration attempts. Please try again later.")
@limiter.limit("20 per hour", error_message="Hourly registration limit exceeded. Please try again later.")
@limiter.limit("50 per day", error_message="Daily registration limit exceeded. Please try again later.")
def register():
    username = bleach.clean(request.args.get('user', ''))
    password = request.args.get('pass', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if User.query.filter_by(name=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    new_user = User(
        name=username,
        password=generate_password_hash(password, method='pbkdf2:sha256:600000'),
        balance=0.0
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 400
    finally:
        db.session.close()  # Explicitly close the session

# Rest of the routes with added rate limiting
@app.route('/login')
@app.route('/login.php')
@limiter.limit("10 per minute")
def login():
    username = bleach.clean(request.args.get('user', ''))
    password = request.args.get('pass', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 401

    user = User.query.filter_by(name=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    response = make_response(jsonify({'message': 'Login successful'}))
    response.set_cookie('session', username, httponly=True)
    return response

@app.route('/manage')
@app.route('/manage.php')
@login_required
@limiter.limit("30 per minute")
def manage(current_user):
    action = bleach.clean(request.args.get('action', ''))
    amount = request.args.get('amount', type=float)

    if action not in ['deposit', 'withdraw', 'balance', 'close']:
        return jsonify({'error': 'Invalid action'}), 400

    if action == 'balance':
        return f"balance={current_user.balance}"

    if action == 'close':
        try:
            db.session.delete(current_user)
            db.session.commit()
            response = make_response('Account closed successfully')
            response.set_cookie('session', '', expires=0)
            return response
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to close account'}), 400
        finally:
            db.session.close()

    if not amount or amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    try:
        if action == 'withdraw':
            if current_user.balance < amount:
                return f"balance={current_user.balance}\nInsufficient funds"
            current_user.balance -= amount
        elif action == 'deposit':
            current_user.balance += amount

        transaction = Transaction(
            user_id=current_user.id,
            type=action,
            amount=amount,
            ip_address=request.remote_addr
        )

        db.session.add(transaction)
        db.session.commit()

        return f"balance={current_user.balance}"

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Transaction failed'}), 400
    finally:
        db.session.close()

@app.route('/logout')
@app.route('/logout.php')
@login_required
def logout(current_user):
    response = make_response('Logout successful')
    response.set_cookie('session', '', expires=0)
    return response


if __name__ == '__main__':
    app.run(host='1.1.1.1', port=80, debug=False)
