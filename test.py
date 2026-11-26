from database import create_connection

connection = create_connection()

if connection:

    print("connection successful")

    connection.close()

else:
    print("connection failed!")