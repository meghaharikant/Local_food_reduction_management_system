from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from .routes import auth_routes, donor_routes, receiver_routes
    app.register_blueprint(auth_routes.auth_bp)
    app.register_blueprint(donor_routes.donor_bp)
    app.register_blueprint(receiver_routes.receiver_bp)

    return app
