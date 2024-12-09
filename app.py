from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from werkzeug.security import generate_password_hash 
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import bcrypt 
from werkzeug.exceptions import BadRequest
from movie_db import get_movie_by_id
from flask_login import current_user
from flask_login import login_user, current_user, login_required
from flask import jsonify
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # To use sessions (replace with a secure key)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User:
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role  # Ensure role is passed to the class

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='movie_review_db'
    )
    connection.cursor(dictionary=True)  # This makes the cursor return dicts
    return connection
   

# MCU Movie Data (hardcoded list of movies)
mcu_movies = []

class User(UserMixin):
    def __init__(self, id, username, role):  # Add 'role' to the constructor
        self.id = id
        self.username = username
        self.role = role  # Set role as an attribute

# Update the user loader function to include 'role'
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return User(id=user['id'], username=user['username'], role=user['role'])  # Include 'role' here
    return None

@app.route('/check-username')
def check_username():
    username = request.args.get('username')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'available': False})
    else:
        return jsonify({'available': True})



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user from the database
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # If user exists and password is correct, log them in
            user_obj = User(id=user['id'], username=user['username'], role=user['role'])
            login_user(user_obj)

            print(f"Logged in as: {current_user.username}, Role: {current_user.role}")  # Log user info

            flash('Login successful!', 'success')

            # Record the login in the login_history table
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO login_history (user_id, login_time) VALUES (%s, %s)", 
                               (current_user.id, datetime.now()))
                conn.commit()

            # Redirect to appropriate page based on the user's role
            if current_user.role == 'admin':
                return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
            else:
                return redirect(url_for('index'))  # Redirect to the home page

        else:
            flash("Invalid username or password!", "danger")
            return redirect(url_for('login'))  # Redirect to login page if credentials are incorrect

    return render_template('login.html')



# Route for Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'user')  # Default role is 'user' if not provided

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        # Password strength check
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password):
            flash("Password must be at least 8 characters long, contain an uppercase letter and a number.", "danger")
            return redirect(url_for('signup'))

        # Check if the username already exists
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists!", "danger")
            conn.close()
            return redirect(url_for('signup'))

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed_password, role))
        conn.commit()

        # Access lastrowid before closing the connection
        user_obj = User(id=cursor.lastrowid, username=username, role=role)

        # Log the user in
        login_user(user_obj)
        flash('Account created and logged in!', 'success')
        
        conn.close()  # Now close the connection after all database operations

        # Redirect to the appropriate page after signup (e.g., home or profile)
        return redirect(url_for('home'))  # Ensure 'home' route exists

    return render_template('signup.html')



@app.route('/home', methods=['GET', 'POST'])
def home():
    search_term = request.args.get('search', '')  # Get search term from the URL if any
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if search_term:
        cursor.execute("SELECT * FROM movies WHERE title LIKE %s", ('%' + search_term + '%',))
    else:
        cursor.execute("SELECT * FROM movies")
    
    movies = cursor.fetchall()
    conn.close()
    
    return render_template('index.html', movies=movies, search_term=search_term)






# Route for Logout
@app.route('/logout')
@login_required
def logout():
    # Save logout time in the login_history table when the user logs out
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE login_history
        SET logout_time = %s
        WHERE user_id = %s AND logout_time IS NULL
    """, (datetime.now(), current_user.id))  # Make sure it's only updated once
    conn.commit()
    conn.close()

    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


# movies

# Home route (display MCU movies)
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    # Get request arguments
    sort_order = request.args.get('sort_order', 'desc')  # Default to 'desc' if no sort order is provided
    search_term = request.args.get('search_term', '')  # Get the search term from the form
    min_rating = request.args.get('min_rating', '')  # Get the minimum rating filter

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Base query for fetching movies
    query = """
        SELECT movies.*, AVG(ratings.rating) AS avg_rating, MAX(ratings.created_at) AS last_rated
        FROM movies
        LEFT JOIN ratings ON movies.id = ratings.movie_id
    """

    params = []

    # Add search term condition if provided
    if search_term:
        query += " WHERE movies.title LIKE %s"
        params.append('%' + search_term + '%')  # Partial matching with wildcard

    # Group the results by movie ID
    query += " GROUP BY movies.id"

    # Add filter for min_rating if provided (use HAVING here for aggregate functions)
    if min_rating:
        query += " HAVING avg_rating >= %s"
        params.append(min_rating)

    # Modify query based on sort order
    if sort_order == 'asc':
        query += " ORDER BY avg_rating ASC"  # Low rated
    else:
        query += " ORDER BY avg_rating DESC"  # Top rated

    # Execute the query with the appropriate parameters
    cursor.execute(query, params)
    movies = cursor.fetchall()

    conn.close()

    # Render the template with the fetched data
    return render_template('index.html', movies=movies, sort_order=sort_order, search_term=search_term, min_rating=min_rating)







# Route to view movie details
@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
def movie_details(movie_id):
    # Establish a connection to the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch movie details from the database
    cursor.execute("SELECT * FROM movies WHERE id = %s", (movie_id,))
    movie = cursor.fetchone()  # Get a single movie

    # Close the cursor and connection
    cursor.close()
    conn.close()

    if not movie:
        return "Movie not found", 404

    # Process trailer URL (same as before)
    trailer_url = movie.get('trailer', '')
    if trailer_url and 'youtube.com/watch' in trailer_url:
        embed_url = trailer_url.replace("watch?v=", "embed/")
        movie['trailer_embed'] = embed_url
    else:
        movie['trailer_embed'] = trailer_url  # Keep the URL as is if not YouTube

    # Handle comment submission
    if request.method == 'POST':
        user_comment = request.form.get('comment')
        if user_comment:
            # Save the comment to the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO comments (movie_id, comment) VALUES (%s, %s)", (movie_id, user_comment))
            conn.commit()
            cursor.close()
            conn.close()

        # Return the updated page with the new comment
        return redirect(url_for('movie_details', movie_id=movie_id))

    # Fetch existing comments for this movie
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM comments WHERE movie_id = %s", (movie_id,))
    comments = cursor.fetchall()
    cursor.close()
    conn.close()

    # Pass the movie data and comments to the template
    return render_template('movie_details.html', movie=movie, comments=comments)



def get_user_rating_for_movie(movie_id, user_id):
    conn = get_db_connection()  # Assuming you have a DB connection function
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT rating
    FROM ratings
    WHERE movie_id = %s AND user_id = %s
    """
    
    cursor.execute(query, (movie_id, user_id))
    rating = cursor.fetchone()  # Returns the rating row, or None if not found

    conn.close()
    
    if rating:
        return rating['rating']  # Return the rating value
    else:
        return None  # If no rating is found for this user


# Route to handle movie comments (POST request)
@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
@login_required
def comment_movie(movie_id):
    # Find the movie by ID (you'll likely retrieve this from the database or some other source)
    movie = next((movie for movie in mcu_movies if movie['id'] == movie_id), None)
    
    if movie:
        if request.method == 'POST':
            # Get the rating from the form
            rating = request.form.get('rating', None)
            comment = request.form.get('comment', None)  # Get the comment from the form
            
            if rating:
                # Store the rating as an integer
                movie['rating'] = int(rating)

            if comment:
                # Store the comment in a list (or database, if you're using one)
                if 'comments' not in movie:
                    movie['comments'] = []
                movie['comments'].append(comment)
            
            # Redirect back to the movie details page with the updated rating and comments
            return redirect(url_for('movie_details', movie_id=movie_id))
    
    return redirect(url_for('home'))


@app.route('/rate_movie/<int:movie_id>', methods=['POST'])
@login_required  # Ensure the user is logged in before submitting the rating
def rate_movie(movie_id):
    rating = request.form['rating']  # Get the rating value from the form
    user_id = current_user.id  # Get the user_id of the logged-in user
    
    # Validate the rating to ensure it's within the expected range (1-5)
    if rating not in ['1', '2', '3', '4', '5']:
        flash("Invalid rating!", "error")
        return redirect(url_for('movie_details', movie_id=movie_id))
    
    # Insert the rating into the database
    insert_rating(movie_id, int(rating), user_id)
    
    flash(f"Your rating of {rating} stars has been saved!", "success")
    return redirect(url_for('movie_details', movie_id=movie_id))  # Redirect to the movie details page


@app.route('/rate_movie/<int:movie_id>', methods=['POST'])
def submit_rating(movie_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You must be logged in to submit a rating!'}), 403  # return error if not logged in
    
    rating = request.form.get('rating')
    
    # Debugging: Log the rating value
    print(f"Rating submitted: {rating}")

    if not rating or int(rating) < 1 or int(rating) > 5:
        return jsonify({'success': False, 'message': 'Invalid rating! Please select a value between 1 and 5.'}), 400

    user_id = session['user_id']  # get the logged-in user's id

    # Check if the user has already rated this movie
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM ratings WHERE user_id = %s AND movie_id = %s', (user_id, movie_id))
    existing_rating = cursor.fetchone()

    if existing_rating:
        # If the user has already rated, update the existing rating
        cursor.execute('UPDATE ratings SET rating = %s WHERE user_id = %s AND movie_id = %s',
                       (rating, user_id, movie_id))
    else:
        # If the user has not rated, insert a new rating
        cursor.execute('INSERT INTO ratings (movie_id, rating, user_id) VALUES (%s, %s, %s)',
                       (movie_id, rating, user_id))

    conn.commit()  # commit changes to the database
    conn.close()  # close the connection

    # Success response
    return jsonify({'success': True, 'message': 'Your rating has been submitted successfully!'}), 200



@app.route('/movie/<int:movie_id>/comment', methods=['POST'])
def submit_comment(movie_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You must be logged in to comment!'}), 403

    comment = request.form['comment']
    user_id = current_user.id  # Assuming you are using Flask-Login

    # Insert the comment into the database
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('''
        INSERT INTO comments (movie_id, user_id, comment)
        VALUES (%s, %s, %s)
    ''', (movie_id, user_id, comment))
    connection.commit()
    cursor.close()

    return jsonify({'success': True, 'message': 'Your comment has been submitted!'}), 200


def insert_rating(movie_id, rating, user_id):
    connection = get_db_connection()  # Get your DB connection
    cursor = connection.cursor()      # Create cursor to interact with the DB
    try:
        cursor.execute('''
            INSERT INTO ratings (movie_id, rating, user_id)
            VALUES (%s, %s, %s)
        ''', (movie_id, rating, user_id))  # Insert the data into the table
        connection.commit()  # Save the changes to the database
    except Exception as e:
        print(f"Error inserting rating: {e}")  # Log any error that occurs
    finally:
        cursor.close()  # Close the cursor
        connection.close()  # Close the connection


@app.route('/toggle_favorite/<int:movie_id>', methods=['POST'])
@login_required
def toggle_favorite(movie_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the movie is already in the user's favorites
    cursor.execute("SELECT * FROM user_favorites WHERE user_id = %s AND movie_id = %s", (current_user.id, movie_id))
    favorite = cursor.fetchone()

    if favorite:
        # If it is, remove it from favorites
        cursor.execute("DELETE FROM user_favorites WHERE user_id = %s AND movie_id = %s", (current_user.id, movie_id))
    else:
        # If it isn't, add it to favorites
        cursor.execute("INSERT INTO user_favorites (user_id, movie_id) VALUES (%s, %s)", (current_user.id, movie_id))

    conn.commit()
    conn.close()

    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    # Fetch the user's favorite movies and ratings from the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get the user's favorite movies
    cursor.execute("""
        SELECT m.title, m.id
        FROM movies m
        JOIN user_favorites uf ON m.id = uf.movie_id
        WHERE uf.user_id = %s
    """, (current_user.id,))
    favorites = cursor.fetchall()

    # Get user ratings
    cursor.execute("""
        SELECT r.rating, m.title
        FROM ratings r
        JOIN movies m ON r.movie_id = m.id
        WHERE r.user_id = %s
    """, (current_user.id,))
    ratings = cursor.fetchall()

    conn.close()

    # Pass current_user and the data to the template
    return render_template('profile.html', user_info=current_user, favorites=favorites, ratings=ratings)












#ADMIN NI GOY-----------------------------------------------------------------


def is_admin(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user and user['is_admin']:
        return True
    return False

# Admin dashboard route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('home'))

    # Fetch the login history
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT lh.id, u.username, lh.login_time, lh.logout_time
        FROM login_history lh
        JOIN users u ON lh.user_id = u.id
        ORDER BY lh.login_time DESC
    """)
    login_history = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', login_history=login_history)


# Login route


# Admin-related routes
@app.route('/add_movie', methods=['GET', 'POST'])
def add_movie():
    if request.method == 'POST':
        # Extract the movie details from the form
        title = request.form['title']
        description = request.form['description']
        release_date = request.form['release_date']
        rating = request.form['rating']
        trailer = request.form['trailer']
        poster = request.form['poster']  # This should match the database column name 'poster'
        
        # Create the SQL query to insert the movie into the database
        query = """
            INSERT INTO movies (title, description, release_date, rating, trailer, poster)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        # Execute the query
        conn = mysql.connector.connect(
            host='localhost',
            user='root',  # Replace with your MySQL username
            password='',  # Replace with your MySQL password
            database='movie_review_db'  # Replace with your database name
        )
        cursor = conn.cursor()
        cursor.execute(query, (title, description, release_date, rating, trailer, poster))  # Using 'poster' here
        conn.commit()
        
        # Close the connection
        cursor.close()
        conn.close()
        
        flash('Movie added successfully!', 'success')
        return redirect(url_for('manage_movies'))
    
    return render_template('add_movie.html')








@app.route('/manage_movies')
def manage_movies():
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='movie_review_db'
    )
    cursor = conn.cursor(dictionary=True)  # Use dictionary=True to fetch rows as dictionaries

    # Fetch all movies from the database
    cursor.execute("SELECT * FROM movies")
    movies = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('manage_movies.html', movies=movies)


@app.route('/edit_movie/<int:movie_id>', methods=['GET', 'POST'])
def edit_movie(movie_id):
    # Connect to the database
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='movie_review_db'
    )
    cursor = conn.cursor(dictionary=True)  # Use dictionary=True to return rows as dicts

    # Fetch the movie from the database
    cursor.execute("SELECT * FROM movies WHERE id = %s", (movie_id,))
    movie = cursor.fetchone()

    if not movie:
        flash('Movie not found!', 'danger')
        return redirect(url_for('manage_movies'))

    if request.method == 'POST':
        # Get form data and update the movie
        title = request.form['title']
        description = request.form['description']
        release_date = request.form['release_date']
        rating = request.form['rating']
        trailer = request.form['trailer']
        poster = request.form['poster']

        update_query = """
            UPDATE movies
            SET title = %s, description = %s, release_date = %s, rating = %s, trailer = %s, poster = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (title, description, release_date, rating, trailer, poster, movie_id))
        conn.commit()
        flash('Movie updated successfully!', 'success')
        return redirect(url_for('manage_movies'))

    cursor.close()
    conn.close()

    # Pass the movie data to the template
    return render_template('edit_movie.html', movie=movie)




@app.route('/delete_movie/<int:movie_id>', methods=['POST'])
@login_required
def delete_movie(movie_id):
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('home'))

    # Delete movie from the database (using MySQL syntax)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Use %s placeholder for MySQL
    cursor.execute("DELETE FROM movies WHERE id = %s", (movie_id,))
    conn.commit()
    conn.close()

    flash('Movie deleted successfully!', 'success')
    return redirect(url_for('manage_movies'))



@app.route('/view_user_ratings')
@login_required
def view_user_ratings():
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('home'))

    # Fetch ratings for all movies from the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT movies.title, ratings.rating, users.username
        FROM ratings
        JOIN movies ON ratings.movie_id = movies.id
        JOIN users ON ratings.user_id = users.id
    ''')
    ratings = cursor.fetchall()
    conn.close()

    # Debugging output
    print(ratings)  # This will print the fetched data

    return render_template('view_user_ratings.html', ratings=ratings)



@app.route('/view_user_comments')
@login_required
def view_user_comments():
    if current_user.role != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('home'))

    # Fetch comments for all movies from the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT movies.title, comments.comment, users.username
        FROM comments
        JOIN movies ON comments.movie_id = movies.id
        JOIN users ON comments.user_id = users.id
    ''')
    comments = cursor.fetchall()
    conn.close()

    return render_template('view_user_comments.html', comments=comments)

@app.route('/view_login_history', methods=['GET', 'POST'])
@login_required
def view_login_history():
    if request.method == 'POST' and 'clear_history' in request.form:
        # Delete all login history records from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM login_history")
        conn.commit()
        conn.close()
        flash("Login history has been cleared!", "success")
        return redirect(url_for('view_login_history'))

    # Fetch the login history sorted by login_time
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT lh.id, lh.user_id, lh.login_time, lh.logout_time, u.username
        FROM login_history lh
        JOIN users u ON lh.user_id = u.id
        ORDER BY lh.login_time DESC
    """)
    login_history = cursor.fetchall()
    conn.close()

    return render_template('view_login_history.html', login_history=login_history)






if __name__ == '__main__':
    app.run(debug=True)
