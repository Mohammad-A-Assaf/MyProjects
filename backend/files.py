from flask import Blueprint, jsonify, request, current_app, send_from_directory, make_response
from database import get_db
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import hashlib
import sqlite3
import uuid
import os

files = Blueprint('files', __name__) 

@files.route('/upload', methods = ['POST'])
@jwt_required()
def file_upload():
    db = get_db()
    print(current_app.config.keys()) # will list all loaded keys in the terminal

    folder = current_app.config['UPLOAD_FOLDER']

    if not folder:
        return {"error":"Upload folder not configured on server"}, 500

    # Get user ID from JWT
    owner_id = get_jwt_identity()

    # Capture the encrypted file
    file_blob = request.files.get('encrypted_file')

    # Generate SHA-256 Hash for files
    file_content = file_blob.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    # Reset file pointer to be able to save after reading
    file_blob.seek(0)

    # capture the metadata 
    wrapped_key = request.form.get('wrapped_key')
    iv = request.form.get('iv')
    original_name_enc = request.form.get('filename_encrypted')

    if not file_blob or not wrapped_key or not iv:
        return jsonify({"error":"Missing metadata"}), 400
    
    # save to local storage
    storage_filename = str(uuid.uuid4()) # using uuid to prevent filename injection attacks e.g., '550e8400-e29b...'
    file_blob.save(os.path.join(folder, storage_filename))


    # Saving metadata to database (files table)
    query = """
    INSERT INTO files (owner_id, filename_enc, wrapped_key, iv, file_hash, storage_path) 
    VALUES(?, ?, ?, ?, ?, ?)
    """

    db.execute(query, (
        owner_id,
        original_name_enc,
        wrapped_key,
        iv,
        file_hash,
        storage_filename
    ))
    db.commit()

    return {"message":"Success"}

@files.route('/my-files', methods = ['GET'])
@jwt_required()
def list_files():
    db = get_db()
    owner_id = get_jwt_identity()

    # Capture rows from the database
    rows = db.execute(
        "SELECT id, filename_enc, created_at FROM files WHERE owner_id = ?", 
        (owner_id,)
    ).fetchall()

    # Convert Sqlite row objects into a list of dictionaries
    files_list = []
    for row in rows:
        files_list.append({
            "id": row["id"],
            "filename_enc": row["filename_enc"],
            "created_at": row["created_at"]
        })

    return jsonify(files_list), 200



@files.route('/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download(file_id):
    db = get_db()
    current_user_id = get_jwt_identity()

    # Fetch metadata and verify ownership
    file_record = db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?", 
        (file_id, current_user_id)
    ).fetchone()

    # Ownership Check
    if not file_record:
        return {"error":"Unauthorized access!"}, 404
    
    # File response
    # Using send_from_directory for efficient streaming
    response = make_response(send_from_directory(
        current_app.config['UPLOAD_FOLDER'],
        file_record['storage_path']
    ))

    # Attach and send metadata to custom http headers
    # Will be read by javascript
    response.headers['X-wrapped-key'] = file_record['wrapped_key'].replace('\n', '').strip()
    response.headers['X-IV'] = file_record['iv'].replace('\n', '').strip()
    response.headers['X-Filename-Enc'] = file_record['filename_enc'].replace('\n', '').strip()


    # Frontend will see these headers
    response.headers['Access-Control-Expose-Headers'] = 'X-Wrapped-Key, X-IV, X-Filename-Enc'

    return response

    
    





