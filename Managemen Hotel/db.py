import MySQLdb
from flask import current_app, g

def connect_db():
    return MySQLdb.connect(
        host="localhost",
        user="root",      # Ganti dengan username MySQL Anda
        password="",    # Ganti dengan password MySQL Anda
        db="db_hotel"
    )

def get_db():
    if 'db' not in g:
        g.db = connect_db()
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_app(app):
    app.teardown_appcontext(close_db)
