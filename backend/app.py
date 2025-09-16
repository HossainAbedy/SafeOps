# backend/app.py
import os
import sys
from pathlib import Path
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import config

# ensure backend directory is on sys.path for relative imports
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# central logger
try:
    from utils.logger import logger
except Exception:
    import logging
    logger = logging.getLogger("safeops")
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(h)
    logger.setLevel(logging.INFO)

def create_app():
    """
    Flask application factory.
    """
    app = Flask(__name__, static_folder=None)

    # JWT config
    app.config["JWT_SECRET_KEY"] = getattr(config, "JWT_SECRET", "change-this-secret-in-prod")
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]
    app.config["PROPAGATE_EXCEPTIONS"] = True

    # CORS - allow frontend localhost during dev
    CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000"]}}, supports_credentials=True)

    # JWT manager
    JWTManager(app)

    # import blueprints
    try:
        from routes.auth_routes import bp as auth_bp
        from routes.scan_routes import bp as scan_bp
        from routes.system_routes import bp as system_bp
    except Exception as e:
        logger.exception("Failed to import blueprints: %s", e)
        raise

    # register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(scan_bp, url_prefix="/scan")
    app.register_blueprint(system_bp, url_prefix="")

    # basic health check
    @app.route("/health")
    def health():
        return jsonify({"ok": True, "data": {"status": "ok"}})

    # endpoint to download a job result JSON
    @app.route("/download/<job_id>")
    def download_job(job_id: str):
        from services import jobs
        job = jobs.get_job(job_id)
        if not job.get("ok"):
            return jsonify(job), 404
        if not job.get("result_file") or not os.path.exists(job["result_file"]):
            return jsonify({"ok": False, "error": "Result file not available"}), 404
        return send_file(job["result_file"], as_attachment=True)

    # simple explain endpoint
    @app.route("/explain")
    def explain():
        return jsonify({"ok": True, "data": {"what": "SafeOps backend with checks.py and job runner"}})

    return app

if __name__ == "__main__":
    app = create_app()
    host = getattr(config, "HOST", "127.0.0.1")
    port = int(getattr(config, "PORT", 5000))
    debug = bool(getattr(config, "DEBUG", True))
    logger.info("Starting SafeOps backend on %s:%s (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug)
