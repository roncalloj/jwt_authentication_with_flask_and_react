"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, TokenBlockedList
from api.utils import generate_sitemap, APIException

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
    get_jti,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import date, time, datetime, timezone

api = Blueprint("api", __name__)
app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)


@api.route("/hello", methods=["POST", "GET"])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route("/signup", methods=["POST"])
def signup():
    email = request.json.get("email", None)
    password = request.json.get("password", None).strip()
    users = User.query.filter_by(email=email).first()
    try:
        password = bcrypt.generate_password_hash(password, rounds=None).decode("utf-8")
        user = User(email=email, password=password, is_active=True)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User registered"}), 201
    except Exception as error:
        db.session.rollback()
        if users:
            return jsonify({"message": "Email already registered"}), 400
        print(error)
        return jsonify({"message": str(error)}), 400


@api.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Wrong email or password"}), 401
    validPassword = bcrypt.check_password_hash(user.password, password)
    if not validPassword:
        return jsonify({"message": "Wrong email or password"}), 401

    access_token = create_access_token(identity=user.id, additional_claims={"role": "admin"})
    access_token_jti = get_jti(access_token)
    refresh_token = create_refresh_token(
        identity=user.id, additional_claims={"access_token": access_token_jti, "role": "admin"}
    )
    return jsonify({"token": access_token, "refresh_token": refresh_token}), 200


@api.route("/hellosecure", methods=["GET"])
@jwt_required()
def handle_hello_secure():
    claims = get_jwt()
    user = User.query.get(get_jwt_identity())
    response_body = {
        "message": "Hello! I'm a message that came from the RESTRICTED backend, check the network tab on the google inspector and you will see the GET request",
        "user_id": get_jwt_identity(),
        "role": claims["role"],
    }

    # return jsonify(response_body), 200
    return jsonify(user.serialize()), 200


@api.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    claims = get_jwt()
    access_token = claims["accessToken"]
    refresh_token = claims["jti"]
    role = claims["role"]
    nowdate = datetime.now(timezone.utc)
    id = get_jwt_identity()
    accessTokenBlocked = TokenBlockedList(token=access_token, created_at=nowdate, email=get_jwt_identity())
    refreshTokenBlocked = TokenBlockedList(token=refresh_token, created_at=nowdate, email=get_jwt_identity())
    db.session.add(accessTokenBlocked)
    db.session.add(refreshTokenBlocked)
    db.session.commit()

    access_token = create_access_token(identity=id, additional_claims={"role": role})
    access_token_jti = get_jti(access_token)
    refresh_token = create_refresh_token(identity=id, additional_claims={"accessToken": access_token_jti, "role": role})
    return jsonify(access_token=access_token)


@api.route("/logout", methods=["POST"])
@jwt_required(verify_type=False)
def destroytoken():
    jwt = get_jwt()["jti"]
    nowdate = datetime.now(timezone.utc)
    tokenBlocked = TokenBlockedList(token=jwt, created_at=nowdate, email=get_jwt_identity())
    db.session.add(tokenBlocked)
    db.session.commit()

    return jsonify({"msg": "Access revoked"}), 200
