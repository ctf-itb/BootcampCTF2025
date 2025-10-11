import os
from flask import Flask

from blueprints.api import api_bp


def create_app() -> Flask:
    app = Flask(__name__)

    app.config["UPLOAD_DIR"] = "/app/internal/assets"
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    app.register_blueprint(api_bp, url_prefix="/api")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)