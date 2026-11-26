import mysql.connector
from mysql.connector import Error

def create_connection():
    try:
        connection = mysql.connector.connect(
            host = "localhost",
            user = "root",
            password = "gloria2005",
            database = "CONTACT_BOOK_DB",
            charset = "utf8"
        )
        return connection
    except Error as error:
        print("database connection failed:", error)
        return None

    