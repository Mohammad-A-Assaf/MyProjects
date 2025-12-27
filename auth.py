from flask import Blueprint, jsonify, request
from passlib.hash import pbkdf2_sha256
from database import get_db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import pyotp



auth = Blueprint('auth', __name__)


# Registeration logic

@auth.route('/register', methods=['POST'])
def register():
    db = get_db()
    data = request.get_json(force=True)
    public_key = data.get('public_key_rsa')

    if not public_key:
        return {"error":"public_key_rsa is missing from request"}, 400

    # Pre-check messages for the user

    existing = db.execute(
        "SELECT username, email FROM users WHERE username = ? OR email = ?",
        (data['username'], data['email'])
    ).fetchone()

    errors = []
    if existing:
        # Check for Both existing
        if existing['username'] == data['username'] and existing['email'] == data['email']:
            errors.append("User already Exists.")
        
        # Check individual conflicts
        if existing['username'] == data['username']:
            errors.append("Username is already taken.")
        
        if existing['email'] == data['email']:
            errors.append("Email already registered.")

    if errors:
        # Return all found errors at once
        return jsonify({"errors": errors}), 409
    
    # Hash password using PBKDF2
    hashed_pwd = pbkdf2_sha256.hash(data['password'])

    # Generate 2FA secret for authenticator
    totp_secret = pyotp.random_base32()

    # Generate the QR code URI
    provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name = data['username'],
        issuer_name = "SecureCloudVault"
    ) 

    # Attempt to Insert
    try:
        db.execute("INSERT INTO users (username, email, password_hash, totp_secret, public_key_rsa) VALUES(?, ?, ?, ?, ?)",
                (data['username'], data['email'], hashed_pwd, totp_secret, public_key)
        )
        db.commit()

        # Return 2FA secret so client can add it to authenticator
        return jsonify({"message":"Registeration Successful",
                        "totp_secret": totp_secret,
                        "qr_uri": provisioning_uri
        }), 201
    
    except Exception as e:

        # Logs actual error to terminal
        print(f"Database Error: {e}")
        return jsonify({"error":"Database error occured"}), 500
    


# login Logic

@auth.route('/login', methods = ['POST'])
def login():
    data = request.get_json()
    db = get_db()

    user = db.execute("SELECT * FROM users WHERE username = ?",
                      (data['username'],)
            ).fetchone()
    
    #email = db.execute("SELECT * FROM users WHERE email = ?",
                       #(data['email'])
            #).fetchone()
    
    # Check user and password

    if user and pbkdf2_sha256.verify(data['password'], user['password_hash']):

        # Check TOTP (6 digit code from authenticator)
        
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(data['otp_code']):

            # If Success: Issue the token
            identity = str(user['id'])
            access_token = create_access_token(identity = identity)
            refresh_token = create_refresh_token(identity = identity)

            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token
            }), 200
        
        return jsonify({"error":"2FA code is invalid"}), 401
    
    return jsonify({"error":"Invalid Username and Password"}), 500

# Refresh logic

@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh = True)
def refresh():

    # Id the user from the valid refresh token
    current_user_id = get_jwt_identity()

    # issue a brand new access token (short lived)
    new_access_token = create_access_token(identity = current_user_id)

    return jsonify({"access_token": new_access_token}), 200

