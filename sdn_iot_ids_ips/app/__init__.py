from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO()


def create_app(config_object=None):
    app = Flask(__name__, template_folder="../../templates", static_folder="../../static")

    if config_object:
        app.config.from_object(config_object)
    else:
        from config.config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    from app.api.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    return app
