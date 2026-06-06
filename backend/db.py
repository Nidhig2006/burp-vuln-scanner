import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT", 3306))
    )

def init_db():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Read and execute schema.sql
        schema_path = os.path.join(
            os.path.dirname(__file__), 
            '..', 
            'database', 
            'database',
            'schema.sql'
        )
        with open(schema_path, 'r') as f:
            sql = f.read()
        
        for statement in sql.split(';'):
            if statement.strip():
                cursor.execute(statement)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Database error: {e}")