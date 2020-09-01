from flask import Flask, request, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///W:/FLASK-rest-api/todo.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Integer)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated_token_required(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        else:
            return jsonify({"message": "token is missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except jwt.ExpiredSignatureError as e:
            return jsonify({"message": "token is invalid"}), 401
        return f(current_user, *args, **kwargs)

    return decorated_token_required


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "not admin user"})
    users = User.query.all()
    output = list(map(lambda user: {'public id': user.public_id, 'name': user.name, 'admin': user.admin}, users))
    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "not admin user"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"})
    output = {
        "name"     : user.name,
        "public_id": user.public_id
    }
    return jsonify({"user": output})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "not admin user"})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "not admin user"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"})
    user.admin = True
    db.session.commit()
    return jsonify({"message": "user promoted"})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "not admin user"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "user has been deleted"})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        # return jsonify({"message": "no user found"})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({"token": token.decode('UTF-8')})
    else:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id)
    output = list(map(lambda items: {"text": items.text, "completed": items.complete, "id": items.id}, todos))
    return jsonify({current_user.name: output})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id).filter_by(id=todo_id).first()
    if not todo:
        return jsonify({"message": f"no item with id {todo_id}"})
    output = {
        "text"    : todo.text,
        "complete": todo.complete,
        "id"      : todo.id
    }
    return jsonify({"item": output})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def update_item(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id).filter_by(id=todo_id).first()
    if not todo:
        return jsonify({"message": f"no item with id {todo_id}"})
    todo.complete = not todo.complete
    db.session.commit()
    return jsonify({"message": f"Update {todo.text}"})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(todo)
    db.session.commit()
    return jsonify({"message": f"created {data['text']}"})


if __name__ == '__main__':
    app.run(debug=True)
