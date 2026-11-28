from database import create_connection
from datetime import datetime, timedelta
import secrets
import hashlib
from mysql.connector import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash   


from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__, static_folder="templates/static")
app.config["SECRET_KEY"] = "contact book secret key"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/add_contact", methods=["GET", "POST"])
def add_contact():

    if 'user_id' not in session:
        flash("Please log in first.", category="error")
        return redirect(url_for("login"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()

        if not name:
            flash("Contact name is required.", category="error")
            return redirect(url_for("add_contact"))

        db = create_connection()

        if db:
            cursor = None

            try:
                cursor = db.cursor()

                query = """
                    INSERT INTO contacts (user_id, name, phone, email)
                    VALUES (%s, %s, %s, %s)
                """

                values = (
                    session['user_id'],
                    name,
                    phone or None,
                    email or None
                )

                cursor.execute(query, values)
                db.commit()

                flash("Contact added successfully!", category="success")
                return redirect(url_for("home"))

            except Exception as error:
                db.rollback()
                print("Add contact error:", error)
                flash("Failed to add contact.", category="error")

            finally:
                if cursor:
                    cursor.close()
                db.close()

        else:
            flash("Database connection failed!", category="error")

    return render_template("add_contact.html")



@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    if request.method == "POST":
        email = request.form.get('email', '').strip().lower()
        firstName = request.form.get('firstName', '').strip()
        password1 = request.form.get('password1', '')
        password2 = request.form.get('password2', '')

        if len(email) < 8:
            flash('email must be greater than 8 characters.', category='error')
        elif len(firstName) < 5:
            flash('firstName must be greater than 4 characters.', category='error')
        elif password1 != password2:
            flash('passwords don\'t match', category='error')
        elif email.count('@') != 1 or '.' not in email.split('@')[1]:
            flash('invalid email address.', category='error')
        elif len(password1) < 8:
            flash('password must be greater than 8 characters.', category='error')
        else:
            db = create_connection()

            if db:
                cursor = db.cursor()
                hashed_password = generate_password_hash(password1)

                try:
                    cursor.execute(
                        "INSERT INTO users (user_name, email, password) VALUES (%s, %s, %s)",
                        (firstName, email, hashed_password)
                    )
                    db.commit()
                    return redirect(url_for('login'))
                    flash('Registration successful!', category='success')
                except IntegrityError:
                    db.rollback()
                    flash(
                        'This email is already registered. Please use another email.',
                        category='error'
                    )
                except Exception as error:
                    db.rollback()
                    print("Registration error:", error)
                    flash('Registration failed. Please try again.', category='error')
                finally:
                    cursor.close()
                    db.close()
            else:
                flash('Database connection failed!', category='error')

    return render_template("sign_up.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not email or not password:
            flash('Please enter your email and password.', category='error')
        else:
            db = create_connection()

            if db:
                cursor = None
                try:
                    cursor = db.cursor(dictionary=True)
                    cursor.execute(
                        "SELECT * FROM users WHERE email = %s",
                        (email,)
                    )
                    user = cursor.fetchone()

                    if user and check_password_hash(user['password'], password):

                        flash('Login successful!', category='success')
                        session['user_id'] = user['user_id']
                        session['email'] = user['email']
                        return redirect(url_for('home'))
                    else:
                        flash('Invalid email or password.', category='error')
                except Exception as error:
                    print("Login error:", error)
                    flash('Login failed. Please try again.', category='error')
                finally:
                    if cursor:
                        cursor.close()
                    db.close()
            else:
                flash('Database connection failed!', category='error')

    return render_template("login.html")
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        db = create_connection()
        if db:
            cursor = db.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (email,)
                )
                user = cursor.fetchone()
                if user:
                    token = secrets.token_urlsafe(32)
                    hashed_token = hashlib.sha256(token.encode()).hexdigest()
                    expiry = datetime.now() + timedelta(minutes=30)
                    cursor.execute(
                        "UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE email = %s",
                        (hashed_token, expiry, email)
                    )
                    db.commit()
                    flash('Account found!', category='success')
                else:
                    flash('No account found with that email.', category='error')
            finally:
                cursor.close()
                db.close()

    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    db = create_connection()
    if not db:
        flash('Database connection failed!', category='error')
        return redirect(url_for('forgot_password'))

    cursor = db.cursor(dictionary=True)
    try:
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        cursor.execute(
            "SELECT * FROM users WHERE reset_token = %s",
            (hashed_token,)
        )
        user = cursor.fetchone()

        if not user or not user['reset_token_expiry'] or user['reset_token_expiry'] < datetime.now():
            flash('Invalid or expired reset link.', category='error')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            password1 = request.form.get('password1') or ''
            password2 = request.form.get('password2') or ''

            if password1 != password2:
                flash('Passwords do not match.', category='error')
            elif len(password1) < 10:
                flash('Password must be at least 10 characters.', category='error')
            else:
                hashed_password = generate_password_hash(password1)
                cursor.execute(
                    "UPDATE users SET password = %s, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = %s",
                    (hashed_password, user['user_id'])
                )
                db.commit()
                flash('Password reset successful!', category='success')
                return redirect(url_for('login'))
    except Exception as error:
        db.rollback()
        print("Password reset error:", error)
        flash('Password reset failed. Please try again.', category='error')
    finally:
        cursor.close()
        db.close()
    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out successfully.', category='success')
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)