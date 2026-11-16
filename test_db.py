
from database import get_connection

conn = get_connection()

if conn:
    print("MySQL connected successfully!")
    print("DigiSakhi database connected successfully!")

    conn.close()
else:
    print("Database connection failed!")
