# coding=utf-8
"""
Flask App with Redis for JWT Token Blacklist
"""
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_refresh_token, \
    create_access_token, get_raw_jwt, get_jti, jwt_required, \
    jwt_refresh_token_required
import redis
from datetime import timedelta


app = Flask(__name__)

# Flask App JWT Configuration
app.config['SECRET_KEY'] = 'ChangeMe'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=60)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=60)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

# Redis Setup
revoked_store = redis.StrictRedis(host='127.0.0.1')


@app.route('/auth/login', methods=['POST'])
def login():
    """
    Login route which accepts username and password
    :return:
    """
    username, password = \
        request.json.get('username'), request.json.get('password')
    if username != 'test' or password != 'test':
        return jsonify({'message': 'Bad Credentials'}), 400
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    access_token_jti = get_jti(encoded_token=access_token)
    refresh_token_jti = get_jti(encoded_token=refresh_token)
    revoked_store.set(access_token_jti, 'false', timedelta(seconds=60))
    revoked_store.set(refresh_token_jti, 'false', timedelta(seconds=60))
    return dict(access_token=access_token, refresh_token=refresh_token), 201


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(token):
    """
    This function is compulsory if JWT_BLACKLIST_ENABLED is enabled
    This func is decorated by decorator in order to check jti status
    :param token:
    :return: Revoked or Not (True/False)
    """
    jti = token.get('jti')
    entry = revoked_store.get(jti)
    if entry is None:
        return True
    return entry == 'true'


@app.route('/logout')
@jwt_required
def logout():
    """
    Logout call for Access Token
    :return:
    """
    jti = get_raw_jwt().get('jti')
    revoked_store.set(jti, 'true', timedelta(seconds=5))
    return jsonify({"msg": "Access token revoked"}), 401


@app.route('/logout2')
@jwt_refresh_token_required
def logout2():
    """
    Logout call for Refresh Token
    :return:
    """
    jti = get_raw_jwt().get('jti')
    revoked_store.set(jti, 'true', timedelta(seconds=5))
    return jsonify({"msg": "Refresh token revoked"}), 401


@app.route('/protected')
@jwt_required
def protected():
    """
    protected Endpoint
    :return:
    """
    return jsonify({'message': "Protected Endpoint"}), 200


@app.route('/')
def home():
    """
    Home Page
    :return:
    """
    return jsonify({'message': 'Home Page'}), 200


if __name__ == '__main__':
    app.run(debug=True)
