# movie_db.py
import mysql.connector
from mysql.connector import Error

# MySQL connection parameters
MYSQL_HOST = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = ""
MYSQL_DB = "movie_review_db"

def create_connection():
    """ Create a connection to the MySQL database. """
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="movie_review_db"
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error: {e}")
        return None

def init_db():
    """ Initialize the database (creating the table if it doesn't exist). """
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS movies (
                          id INT AUTO_INCREMENT PRIMARY KEY,
                          title VARCHAR(255) NOT NULL,
                          release_date DATE,
                          overview TEXT)''')
        connection.commit()
        cursor.close()
        connection.close()

def add_movie(title, release_date, overview):
    """ Add a new movie to the database. """
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO movies (title, release_date, overview) VALUES (%s, %s, %s)",
                       (title, release_date, overview))
        connection.commit()
        cursor.close()
        connection.close()

def get_movie_by_id(movie_id):
    """ Get a movie's details by ID from the database. """
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM movies WHERE id = %s", (movie_id,))
        movie = cursor.fetchone()
        cursor.close()
        connection.close()
        return movie
