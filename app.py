from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from helpers import login_required

from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if(request.method == "POST"):
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        row = db.execute("SELECT * FROM users WHERE email =?;", email)
        if(not username or not password or not email):
            return render_template("register.html",error="Empty Fields")

        if(len(row) == 1):
            return render_template("register.html",error="Email Already Used")


        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username,email,hash) VALUES (?,?,?);", username, email, hash)

        row = db.execute("SELECT * FROM users WHERE email=?", email)[0]
        print(row)
        session["user_id"] = row["id"]
        return redirect("/")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username and password was submitted
        if not request.form.get("email") or not request.form.get("password"):
            return render_template("login.html", error="Invalid Email or password")


        # Query database for email
        row = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))
        # Ensure email exists and password is correct
        if len(row) != 1:
            return render_template("login.html", error="Invalid Email or password")

        row = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))[0]
        print(row)
        #Check password    
        if not check_password_hash(row["hash"], (request.form.get("password"))):
            return render_template("login.html", error="Invalid Email or password")
        # Remember which user has logged in
        session["user_id"] = row["id"]

        print(session)
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/about") 
def about():
    return render_template("about.html")       

@app.route("/shop") 
def shop():
    return render_template("shop.html")       
    