import os
import re
import requests

from flask import Flask, render_template, request, url_for, redirect, session # gives access to a variable called `session`
                                                                              # which can be used to keep vaules that are specific to a particular user
from flask_session import Session # an additional extension to sessions which allows them
                                  # to be stored server-side
#from tempfile import mkdtemp
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import *
from datetime import datetime

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["shuffle"] = filter_shuffle
app.jinja_env.filters["time"] = convert

# Configure session to use filesystem
#app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set time zone
os.environ['TZ'] = 'Europe/London'

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

# reCAPTCHA Site Key
reCaptcha_SITE_KEY = "" # UPDATE THIS

# Routes
##### MORE #####
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/profile/<username>', methods=["GET", "POST"])
@login_required
def profile(username):
    """USER's PROFILE"""

    # Ensure user exists
    user = db.execute("""SELECT username, password, email, created_on, last_login,
                            (SELECT name FROM roles
                             INNER JOIN user_roles ON user_roles.role_id = roles.id
                             WHERE user_roles.user_id IN (SELECT id FROM users WHERE username=:username)) as role,
                            (SELECT COUNT(*) FROM quizzes WHERE user_id = (SELECT id FROM users WHERE username=:username) AND submitted IS NOT NULL) as total_submission,
                            (SELECT COUNT(*) FROM quizzes WHERE user_id = (SELECT id FROM users WHERE username=:username) AND score = questions) as total_max_score
                         FROM users
                         WHERE username=:username""",
                         {"username": username}).fetchone()

    if user is None:
        return redir("No user found.", url_for('index'))

    if request.method == "POST":
        # Ensure POST method is available only for the personal profile
        if user.username != session["username"]:
            return redir("You cannot modify this profile.")

        # Check captcha status
        if not captcha_check(request.form.get("g-recaptcha-response")):
            return redir("Captcha verification failed. Please try again.")

        """PASSWORD"""
        if request.form.get("old-password"): # if True then user wants to change the password
            # Ensure the password is good
            if not check_password_hash(user.password, request.form.get("old-password")):
                return redir("Wrong password!", url_for('profile', username=session["username"]))

            # Ensure password and confirmation was submitted
            if not request.form.get("new-password") or not request.form.get("conf-password"):
                return redir("Please fill in the new password and confirmation field.", url_for('profile', username=session["username"]))

            password = request.form.get("new-password")
            confirmation = request.form.get("conf-password")

            # Ensure password and confirmation are the same
            if password != confirmation:
                return redir("New password and confirmation don't match.", url_for('profile', username=session["username"]))

            # Ensure strong password was submitted
            # Minimum eight characters, at least one upper case English letter, one lower case English letter, one number and one special character
            pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,15}$"
            match = re.search(pattern, password)

            if not match:
                return redir("Password requirements not met.", url_for('profile', username=session["username"]))

        """IF NO ERRORS"""
        # Create a new user account
        user = db.execute("UPDATE users SET password = :password WHERE id = :id",
                            {"password": generate_password_hash(password), "id": session["user_id"]})
        db.commit()

        # Redirect to home page
        return redir("Profile updated!", url_for('profile', username=session["username"]))

    return render_template("profile.html", user=user, SITE_KEY=reCaptcha_SITE_KEY)

##### Hall of Fame #####
@app.route("/hof/today")
@login_required
def hof_today():
    """PLAYER STATISTICS"""
    rows = db.execute("""SELECT username, name AS category, questions, difficulty, score, EXTRACT(EPOCH FROM (submitted - created)) as time FROM quizzes
                         INNER JOIN users ON quizzes.user_id = users.id
                         INNER JOIN quizzes_categories ON quizzes.cat_id = quizzes_categories.id
                         WHERE submitted >= CURRENT_DATE
                         ORDER BY submitted DESC
                         LIMIT 50""").fetchall()

    return render_template("hof.html", title="Today's Latest 50 Submissions", short = "Today", rows = rows)

@app.route("/hof/top50", methods=["GET", "POST"])
@login_required
def hof_top50():
    """PLAYER STATISTICS"""
    # Ensure method is POST
    if request.method != "POST":
        return redirect(url_for('hof_top50_query'))

    # Check captcha status
    if not captcha_check(request.form.get("g-recaptcha-response")):
        return redir("Captcha verification failed. Please try again.")

    # Ensure number of question was submitted
    if not request.form.get("questions"):
        return redir("Number of questions was blank.")

    # Ensure category was submitted
    elif not request.form.get("category"):
        return redir("Category was not selected.")

    # Ensure difficulty was submitted
    elif not request.form.get("difficulty"):
        return redir("Difficulty was not selected.")

    # Ensure number of wrong answers was submitted
    elif not request.form.get("wrong_a"):
        return redir("Number of wrong questions was blank.")

    # Save form details
    else:
        questions = request.form.get("questions")
        category = request.form.get("category")
        difficulty = request.form.get("difficulty")
        wrong = request.form.get("wrong_a")

    # Ensure number of wrong questions is not greater than the number of total questions
    if int(wrong) > int(questions):
        return redir("Number of wrong questions cannot be greater than the number of total questions.")

    # Extract data from database
    try:
        rows = db.execute("""SELECT username, name AS category, questions, difficulty, score, EXTRACT(EPOCH FROM (submitted - created)) as time FROM quizzes
                             INNER JOIN users ON quizzes.user_id = users.id
                             INNER JOIN quizzes_categories ON quizzes.cat_id = quizzes_categories.id
                             WHERE questions = :questions AND cat_id = :category AND difficulty = :difficulty AND score = :score AND submitted IS NOT NULL
                             ORDER BY time ASC
                             LIMIT 50""",
                             {"questions": questions, "category": category, "difficulty": difficulty, "score": int(questions) - int(wrong)}).fetchall()
    except:
        return redir('One or more query parameters are not valid. Try again.')

    # Get 'category' name from int
    category_name = db.execute("SELECT name FROM quizzes_categories WHERE id = :id", {"id": category}).fetchone()[0]

    return render_template("hof.html", title=f"Top 50 - {questions} {category_name} {difficulty} questions", short=f"Top50 - {questions} {category_name} {difficulty}", rows = rows)

@app.route("/hof/top50/query")
@login_required
def hof_top50_query():
    # Extract quizzes categories
    rows = db.execute("SELECT * FROM quizzes_categories WHERE id != 0 ORDER BY name").fetchall()

    return render_template("hof_query.html", categories=rows, difficulties=["mix", "easy", "medium", "hard"], SITE_KEY=reCaptcha_SITE_KEY)

##### QUIZ #####
@app.route("/play", methods = ["GET", "POST"])
@login_required
def play():
    """PLAY QUIZ"""

    if request.method == "POST":
            # Ensure session["quiz"] is saved to a variable before deletion
            data = session["quiz"].json()
            del session["quiz"]

            total_right_answers = 0 # variable to count the number of correct answers

            # Loop through each question
            for i in range(len(data["results"])):
                q = data["results"][i] # save the question into a dictionary

                # Count number of possible correct answers
                if isinstance(q["correct_answer"], str):
                    total_answers = len(q["incorrect_answers"]) + 1 # incorrect answers + 1 correct answer
                else:
                    total_answers = len(q["incorrect_answers"]) + len(q["correct_answer"])

                # List to store the answers selected by the user
                q["user_answer"] = []

                # Go through each individual answer from 1 to 4
                for j in range(1, total_answers+1):
                    if request.form.get(f"q{i}a{j}"):
                        q["user_answer"].append(request.form.get(f"q{i}a{j}")) # save it in the above variable if it's selected

            # Loop again through each question and compare the results
            for q in data["results"]:
                # If correct_answer is a list ie if more than one correct answer is available
                if isinstance(q["correct_answer"], list):
                    # Ensure the difference between the correct_answer list and user_choice list is 0, meaning no difference
                    if len(list(set(q["correct_answer"]) - set(q["user_choice"]))) != 0:
                        q["user_choice"] = "wrong"
                        continue

                # If is only one correct answer
                else:
                    # Ensure user submitted an answes and ensure the correct_answer matches user's answer
                    if len(q["user_answer"]) != 1 or q["correct_answer"] != q["user_answer"][0]:
                        q["user_choice"] = "wrong"
                        continue

                # If no error occur then user's answer is right and increment the total number of right answers
                q["user_choice"] = "right"
                total_right_answers += 1

            # Update the quiz's submitted date and the score
            db.execute("UPDATE quizzes SET submitted = :date, score = :score WHERE user_id = :user AND id = :id",
                        {"date": datetime.now(), "score": total_right_answers, "user": session["user_id"], "id": session["quiz_id"][0]})
            db.commit()

            # Calculate the time required to complete the quiz
            seconds = round(db.execute("SELECT EXTRACT(EPOCH FROM (submitted - created)) FROM quizzes WHERE id = :id",
                                {"id": session["quiz_id"][0]}).fetchone()[0])

            # Display the results
            return render_template("quiz-result.html", data = data, total = total_right_answers, time = convert(seconds))

    if "quiz" not in session:
        # Redirect user to create a new quiz
        return redirect(url_for("new_quiz"))

    return render_template("quiz-play.html", data = session["quiz"].json())

@app.route("/new-quiz", methods=["GET", "POST"])
@login_required
def new_quiz():
    """Start a new quiz"""

    if request.method == "POST":
        # Check captcha status
        if not captcha_check(request.form.get("g-recaptcha-response")):
            return redir("Captcha verification failed. Please try again.")

        """NEW QUIZ FORM"""
        # Ensure number of question was submitted
        if not request.form.get("questions"):
            return redir("Number of questions was blank.")

        # Ensure category was submitted
        elif not request.form.get("category"):
            return redir("Category was not selected.")

        # Ensure difficulty was submitted
        elif not request.form.get("difficulty"):
            return redir("Difficulty was not selected.")

        # Save form details
        else:
            questions = request.form.get("questions")
            category = request.form.get("category")
            difficulty = request.form.get("difficulty")

        # Check for token key
        if "trivia_token" not in session:
            generate_token()

        """RETRIEVE QUESTIONS"""
        # Make API call
        if difficulty != "mix":
            call = requests.get("https://opentdb.com/api.php", params={"amount": questions, "category": category, "difficulty": difficulty, "token": session["trivia_token"]})
        else:
            call = requests.get("https://opentdb.com/api.php", params={"amount": questions, "category": category, "token": session["trivia_token"]})

        # Check API status
        if check_api_code(call):
            # Insert quiz into the database
            session["quiz_id"] = db.execute("INSERT INTO quizzes (user_id, cat_id, questions, difficulty, created) VALUES (:user, :cat, :questions, :difficulty, :created) RETURNING id",
                                            {"user": session["user_id"], "cat": category, "questions": questions, "difficulty": difficulty, "created": datetime.now()}).fetchone()
            db.commit()

            # Start a new game
            session["quiz"] = call
            return redirect(url_for("play"))

    # Delete current quiz
    if "quiz" in session:
        del session["quiz"]

    # Extract quizzes categories
    rows = db.execute("SELECT * FROM quizzes_categories WHERE id != 0 ORDER BY name").fetchall()

    return render_template("quiz-new.html", categories=rows, difficulties=["mix", "easy", "medium", "hard"], SITE_KEY=reCaptcha_SITE_KEY)

##### Login & Register #####
@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to home page
    return redir("You have successfully logged out!", url_for("index"))

@app.route("/login", methods=["GET", "POST"])
@not_logged_in
def login():
    """Log user in"""

    if request.method == "POST":
        # Check captcha status
        if not captcha_check(request.form.get("g-recaptcha-response")):
            return redir("Captcha verification failed. Please try again.")

        # Ensure email was submitted
        if not request.form.get("email"):
            return redir("Please fill in the email field.")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return redir("Please fill in the password field.")

        # Save form details
        email = request.form.get("email")
        password = request.form.get("password")

        # Ensure account exists
        account = db.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchone()

        if account is None:
            return redir("No account found.")

        # Verify password
        if not check_password_hash(account.password, password):
            return redir("Wrong password!")

        # If no error, then log the user in
        session["user_id"] = account.id
        session["username"] = account.username

        # Update last login
        db.execute("UPDATE users SET last_login = :time WHERE id = :id", {"time": datetime.now(), "id": session["user_id"]})
        db.commit()

        # Redirect to home page
        return redir("You have successfully logged in!", url_for("index"))

    return render_template("login.html", SITE_KEY=reCaptcha_SITE_KEY)

@app.route("/register", methods=["GET", "POST"])
@not_logged_in
def register():
    """Register user"""

    if request.method == "POST":
        # Check captcha status
        if not captcha_check(request.form.get("g-recaptcha-response")):
            return redir("Captcha verification failed. Please try again.")

        """USERNAME"""
        # Ensure username was submitted
        if not request.form.get("username"):
            return redir("Please fill in the username field.")

        username = request.form.get("username")

        # Ensure username is valid
        # Alphanumeric string that may include _ and - having a length of 3 to 16 characters.
        pattern = "^[a-z0-9_-]{3,15}$"
        match = re.search(pattern, username)

        if not match:
            return redir("Username is not valid.")

        """EMAIL"""
        # Ensure email was submitted
        if not request.form.get("email"):
            return redir("Please fill in the email field.")

        email = request.form.get("email")

        # Ensure email is valid
        pattern = "[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+"
        match = re.search(pattern, email)

        if not match:
            return redir("Email is not valid.")

        """PASSWORD"""
        # Ensure password and confirmation was submitted
        if not request.form.get("password") or not request.form.get("confirmation"):
            return redir("Please fill in the password and confirmation field.")

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password and confirmation are the same
        if password != confirmation:
            return redir("Passwords don't match.")

        # Ensure strong password was submitted
        # Minimum eight characters, at least one upper case English letter, one lower case English letter, one number and one special character
        pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,15}$"
        match = re.search(pattern, password)

        if not match:
            return redir("Password requirements not met.")

        """ACCOUNT CHECKS"""
        # Check if an account with the provided username already exists in the database
        account = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchone()
        if account is not None:
            return redir("An account already exists with this username. Please use a different username or login.")

        # Check if an account with the provided email already exists in the database
        account = db.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchone()
        if account is not None:
            return redir("An account already exists with this email. Please use a different email address or login.")

        """IF NO ERRORS"""
        # Create a new user account
        user = db.execute("INSERT INTO users (username, email, password, created_on) VALUES (:username, :email, :password, :created) RETURNING id",
                            {"username": username, "email": email, "password": generate_password_hash(password), "created": datetime.now()}).fetchone()
        db.commit()

        # Assign role
        db.execute("INSERT INTO user_roles (user_id, role_id, grant_date) VALUES (:user, :role, :date)",
                    {"user": user[0], "role": 1, "date": datetime.now()})
        db.commit()

        # Redirect to home page
        return redir("You registered successfully! Please login to access the website.", url_for("index"))

    return render_template("register.html", SITE_KEY=reCaptcha_SITE_KEY)
