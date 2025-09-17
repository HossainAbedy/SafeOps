# backend/routes/auth_routes.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from utils.logger import logger
import config


bp = Blueprint("auth", __name__, url_prefix="/auth")


# NOTE: simple in-memory user store for scaffold. Replace with DB in prod.
_USERS = {
"admin": {"password": "admin"}
}


@bp.route("/login", methods=["POST"])
def login():
    body = request.json or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"}), 400
    user = _USERS.get(username)
    if not user or user.get("password") != password:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401
    token = create_access_token(identity=username)
    return jsonify({"ok": True, "data": {"token": token}})