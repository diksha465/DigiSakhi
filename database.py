
import mysql.connector

def get_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="digisakhi_db"
        )

        return conn

    except mysql.connector.Error as error:
        print("Database connection error:", error)
        return None
