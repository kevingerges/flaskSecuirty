# init_db.py
import os
from app import app, db
from sqlalchemy import text


def init_db():
    # Ensure instance path exists
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    with app.app_context():
        # Drop all tables if they exist
        db.drop_all()

        # Create all tables fresh
        db.create_all()

        # Create trigger after tables are created
        db.session.execute(text("""
            CREATE TRIGGER IF NOT EXISTS prevent_balance_manipulation
            BEFORE UPDATE ON users
            FOR EACH ROW
            BEGIN
                SELECT CASE
                    WHEN NEW.balance < 0 THEN
                        RAISE(ABORT, 'Balance cannot be negative')
                END;
            END;
        """))

        db.session.commit()
        print("Database initialized successfully!")


if __name__ == '__main__':
    try:
        # Delete existing database file
        db_path = os.path.join(app.instance_path, 'bank.db')
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"Removed existing database at {db_path}")

        init_db()
    except Exception as e:
        print(f"Error initializing database: {str(e)}")