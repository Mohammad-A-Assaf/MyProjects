import sqlite3
from flask import g, current_app    


# How to get the database
def get_db():
    if 'db' not in g:
        # Use current_app to avoid circular imports
        g.db = sqlite3.connect(
            current_app.config['DATABASE_PATH'],
            detect_types = sqlite3.PARSE_DECLTYPES
        )

        # Allows accessing data by name: row['username']
        g.db.row_factory = sqlite3.Row
    return g.db
    
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()