from app import app, db
from flask import request, jsonify
from models import User
from passlib.hash import bcrypt


# Criar usuario
@app.route('/api/register', methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = bcrypt.hash(data.get("password"))

    # Verifica se ja tem um usuario com o mesmo nome
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Usuário já cadastrado!'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': 'Seja bem-vindo!'}), 201


# Realizar o login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    # Verifica se tem usuario e se a senha é a mesma.
    if user and bcrypt.verify(password, user.password):
        return jsonify({'success': 'Bem-vindo de volta!'}), 200

    return jsonify({'error': 'Dados incorretos!'}), 400
