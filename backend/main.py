from flask import Flask, request, jsonify,g
from passlib.hash import pbkdf2_sha256
from functools import wraps
from auth import auth # Import the blueprint
from database import close_db
from extensions import jwt
from files import files
from datetime import timedelta
from flask_cors import CORS
import os



def create_app():
    app = Flask(__name__)

    # Enabling CORS for all routes and allow custom headers we created
    CORS(app, expose_headers=["X-Wrapped-Key", "X-IV", "X-Filename-Enc"])

    # Loads DATABASE_PATH from .env 
    app.config.from_prefixed_env()

    # Register the teardown to close the DB after every request
    app.teardown_appcontext(close_db)

    # Initialize extensions from extensions.py
    jwt.init_app(app)

    # Registering the Blueprints
    app.register_blueprint(auth, url_prefix = '/api/auth')
    app.register_blueprint(files, url_prefix = '/api/files')

    # fallback check
    if not app.config.get('UPLOAD_FOLDER'):
        app.config['UPLOAD_FOLDER'] = 'uploads'

    # Create the folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Access token Expiration
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

    

    
    return app

    