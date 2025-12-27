import sqlite3

def setup_database():

    # Connect and create the database file(if not already created)

    con = sqlite3.connect('secure.db')
    cursor = con.cursor()

    # Create the USERS table
    # Stores authentication data and the RSA public key

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            public_key_rsa TEXT NOT NULL -- Stores the 4096-bit SPKI string from the client
        )
    ''')

    # Create the FILES table
    # Stores metadata required for the client to decrypt later

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename_enc TEXT NOT NULL, -- The filename is encrypted locally
            wrapped_key TEXT NOT NULL, -- The AES-256 key encrypted with RSA-4096
            iv TEXT NOT NULL, -- The 12-byte AES-GCM nonce
            file_hash TEXT NOT NULL, -- SHA-256 for integrity verification
            storage_path TEXT NOT NULL, -- local path for the uploads
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    ''')

    con.commit()
    con.close()
    print(f"Database 'vault.db' initialized with secure schema.")

if __name__ == "__main__":
    setup_database()
