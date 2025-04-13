from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(current_user, *args, **kwargs)

    return decorated


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')

            if not token:
                return jsonify({'message': 'Token is missing!'}), 403

            try:
                token = token.split(" ")[1]
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = User.query.get(data['user_id'])
                if current_user.role != role:
                    return jsonify({'message': 'Insufficient permissions!'}), 403
            except:
                return jsonify({'message': 'Token is invalid!'}), 403

            return f(current_user, *args, **kwargs)

        return decorated
    return decorator


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return redirect(url_for('index'))


def verify_token(token):
    if not token:
        return None, 'Token is missing!'

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.get(data['user_id'])
        return current_user, None
    except:
        return None, 'Token is invalid!'


def protected_route(current_user):
    if not current_user:
        return jsonify({'message': 'Token is invalid!'}), 403
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})


def admin_route(current_user):
    if not current_user:
        return jsonify({'message': 'Token is invalid!'}), 403
    if current_user.role != 'admin':
        return jsonify({'message': 'Insufficient permissions!'}), 403
    return jsonify({'message': f'Hello, {current_user.username}! This is the admin route.'})


@app.route('/protected', methods=['GET'])
def handle_protected():
    token = request.args.get('token')
    current_user, error = verify_token(token)
    if error:
        return jsonify({'message': error}), 403
    return protected_route(current_user)


@app.route('/admin', methods=['GET'])
def handle_admin():
    token = request.args.get('token')
    current_user, error = verify_token(token)
    if error:
        return jsonify({'message': error}), 403
    return admin_route(current_user)


if __name__ == '__main__':
    with app.app_context():
        import os
        os.makedirs(os.path.join(app.instance_path, 'templates'), exist_ok=True)
        db.create_all()
    app.run(debug=True)