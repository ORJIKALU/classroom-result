import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, make_response
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
import re
import datetime
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
import random
import string
from requests.models import Response

from operator import itemgetter, attrgetter






from functions import apology, login_required, database, random_string_generator, render_portfolio, term_tables, drop_tables

# Configure application
app = Flask(__name__)


# generate confirmation token given email	
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

# return email given confirmation token
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email
# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "precious_two"
app.config["SECURITY_PASSWORD_SALT"] = "precious"
Session(app)


# send message to email
def send_email(to, subject, template, sender_email):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=sender_email
    )
    mail.send(msg)


app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = "orjikalukelvin@gmail.com",
    MAIL_PASSWORD = "googlevenuse123",
))

mail = Mail(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///schools.db")

info = {}
subject_info = {}
error = None

@app.route("/")
def index():
    if not request.cookies.get("series_id"):
        session.clear()
        return render_template("login.html") 
    else:
        user = db.execute("SELECT * FROM main_table WHERE token_id = :series", series = request.cookies.get("series_id"))
        if len(user) != 1:
            session.clear()
            return render_template("login.html")
        if not check_password_hash(user[0]["token"], request.cookies.get("main_token")):
            session.clear()
            error = " theft dedicated, leave the site"
            return render_template("login.html", error = error)
        session["user_id"] = user[0]["id"]
        # if account is confirmed render this
        if(user[0]["confirmed"]== "true"):
            tables = database(str(0))
            schoolClass = tables["classes"]
            rows = db.execute("SELECT * FROM main_table WHERE id=:id", id = session["user_id"])
            classRows = db.execute("SELECT * FROM :classes ",classes = schoolClass)
            # return render portfolio
            return render_template("portfolio.html", schoolInfo = rows, clas = classRows)
        # else if account is not confirmed render unconfirmed view
        else:
            return redirect('/unconfirmed')


        
        


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return render_template("/login.html")
    
@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure firstname was submitted
        if not request.form.get("firstname"):
            error = "you must provide  firstname"
            return render_template("register.html", error = error)
        # Ensure surname was submitted
        if not request.form.get("surname"):
            error = "you must provide your surname"
            return render_template("register.html", error = error)
        # Ensure email was submitted
        if not request.form.get("email"):
            error = "you must provide email"
            return render_template("register.html", error = error)
        # Ensure phone number was submitted
        if not request.form.get("phone_number"):
            error = "you must provide phone number"
            return render_template("register.html", error = error)
        if not request.form.get("school_name"):
            error = "you must provide school name"
            return render_template("register.html", error = error)
        # Ensure address was submitted
        if not request.form.get("address"):
            error = "you must provide school address"
            return render_template("register.html", error = error)
        # Ensure city was submitted
        if not request.form.get("city"):
            error = "you must provide city"
            return render_template("register.html", error = error)
        # Ensure state was submitted
        if not request.form.get("state"):
            error = "you must provide school's state"
            return render_template("register.html", error = error)
        # Ensure term was submitted
        if not request.form.get("term"):
            error = "you must provide current term"
            return render_template("register.html", error = error)
        # ensure session was submitted
        if not request.form.get("school_session"):
            error = "you must provide current session"
            return render_template("register.html", error = error)
        # ensure username was submitted
        if not request.form.get("username"):
            error = "you must provide a unique username"
            return render_template("register.html", error = error)
        # ensure the username is not taken
        username_check = db.execute("SELECT * FROM main_table WHERE username = :username", username = request.form.get("username").lower())
        if  len(username_check) > 0:
            error = "username: "+request.form.get("username")+" already taken, choose another one"
            return render_template("register.html", error = error)
        email_check = db.execute("SELECT * FROM main_table WHERE email = :email", email = request.form.get("email").lower())
        if  len(email_check) > 0:
            error = "Another account has been opened with email: "+request.form.get("email")
            return render_template("register.html", error = error)
        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            error = "you must provide confirmation"
            return render_template("register.html", error = error)
        if not request.form.get("admin_password"):
            error = "you must provide admin password"
            return render_template("register.html", error = error)
        if not request.form.get("admin_password_confirmation"):
            error = "you must provide admin password confirmation"
            return render_template("register.html", error = error)

        if (request.form.get("admin_password") != request.form.get("admin_password_confirmation")):
            error = "admin password and confirmation do not match"
            return render_template("register.html", error = error)

        # Ensure password and confirmation match
        if (request.form.get("password") != request.form.get("confirmation")):
            error = "staff password and confirmation do not match"
            return render_template("register.html", error = error)
            
        # Ensure admin_password and password do not match
        if (request.form.get("password") == request.form.get("admin_password")):
            error = "staff password must be different from admin password"
            return render_template("register.html", error = error)
        password = request.form.get("password")
        if len(password) < 8:
            error = "Make sure your password is at lest 8 letters"
            return render_template("register.html", error = error)
        admin_password = request.form.get("admin_password")
        if len(admin_password) < 8:
            error = "Make sure your password is at lest 8 letters"
            return render_template("register.html", error = error)
        if re.search('[0-9]',admin_password) is None:
            error = "Make sure your password contains at least one number"
            return render_template("register.html", error = error)
        if re.search('[A-Z]',admin_password) is None: 
            error = "Make sure your password contains at least one alphabet"
        if re.search('[a-z]',admin_password) is None: 
            error = "Make sure your password contains at least one alphabet"
            return render_template("register.html", error = error)
        token = generate_confirmation_token(request.form.get("email"))
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('confirm_email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(request.form.get("email"), subject, html, 'classresultest@gmail.com')
        db.execute("INSERT INTO main_table (school_name, email,username, password,phone_number,address,city,state,admin_password,surname, firstname, othername,current_session,current_term, registered_on) VALUES (:schoolname, :email, :username, :hash, :phone, :address, :city, :state, :adminPassword, :surname, :firstname, :othername,:current_session,:term, :registered_on)", schoolname = request.form.get("school_name").upper(), email= request.form.get("email").lower(), username = request.form.get("username").lower(), hash = generate_password_hash(request.form.get("password")), phone = request.form.get("phone_number"), address = request.form.get("address").upper(), city=request.form.get("city"), state=request.form.get("state"), adminPassword = generate_password_hash(request.form.get("admin_password")), surname = request.form.get("surname").upper(), firstname = request.form.get("firstname").upper(),othername = request.form.get("othernames").upper(),current_session = request.form.get("school_session"),term=request.form.get("term"), registered_on = datetime.datetime.now())
        # Query database for username
        rows = db.execute("SELECT * FROM main_table WHERE username = :username",username=request.form.get("username").lower())
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        tables = database(str(0))
        column = request.form.get("school_session")+"_"+str(request.form.get("term"))
        db.execute("CREATE TABLE :sessions ('id' INTEGER PRIMARY KEY NOT NULL, :column TEXT)", sessions = tables["sessions"], column=column)
        db.execute("CREATE TABLE :classes ('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,'identifier' TEXT )", classes = tables["classes"])
        db.execute("CREATE TABLE :setting ('id' INTEGER PRIMARY KEY NOT NULL, 'classname' TEXT, 'grading_type' INTEGER, 'comment_lines' INTEGER, 'subject_position' INTEGER DEFAULT 1,'student_position' INTEGER DEFAULT 1, 'surname' TEXT, 'firstname' TEXT,'othername' TEXT,'password' TEXT,'section' TEXT, 'ca' INTEGER, 'test' INTEGER,'exam' INTEGER)", setting = tables["settings"])

        return render_template("unconfirmed.html", schoolInfo=rows)
    else:
        return render_template("register.html")


@app.route("/confirm_email", methods=["GET", "POST"])
def confirm_email():
    token = request.args.get('token')
    email = confirm_token(token)
    if  not email:
        error = 'The confirmation link is invalid or has expired.'
    else:
        user = db.execute("SELECT * FROM main_table WHERE email=:email", email = email)
        if user[0]["confirmed"] == "true":
            error = 'Account already confirmed. Please login.'
        else:
            db.execute("UPDATE main_table SET confirmed = :true WHERE email=:email ", email = email, true="true")
            db.execute("UPDATE main_table SET confirmed_on = :date WHERE email=:email ",email = email, date = datetime.datetime.now())
            error = 'You have confirmed your account.  Thanks!'
    session.clear()
    return render_template('login.html',error=error)

@app.route("/unconfirmed", methods=["GET", "POST"])
def unconfirmed():
    user = db.execute("SELECT * FROM main_table WHERE id=:id", id = session["user_id"])
    if user[0]["confirmed"] == "true":
        rows = db.execute("SELECT * FROM main_table WHERE id = :id",id = session["user_id"])
        return render_template("portfolio.html", schoolInfo = rows)
    rows = db.execute("SELECT * FROM main_table WHERE id = :id",id = session["user_id"])
    error = "Your account have not been confirmed and you dont have full access to it"
    return render_template('unconfirmed.html', schoolInfo=rows)

@app.route("/resend_confirmation", methods=["GET", "POST"])
def resend_confirmation():
    user = db.execute("SELECT * FROM main_table WHERE id=:id", id = session["user_id"])
    token = generate_confirmation_token(user[0]["email"])
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('confirm_email.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(user[0]["email"], subject, html,'classresultest@gmail.com')
    flash('A new confirmation email has been sent.', 'success')
    return redirect('/unconfirmed')


@app.route("/username_check", methods=["POST"])
def register_check():
    if request.method == "POST":
        # Query database for username
        rows = db.execute("SELECT * FROM main_table WHERE username = :username",username=request.form.get("username").lower())
        if len(rows) == 0:
            return "true"
        else:
            return "false"


@app.route("/email_check", methods=["POST"])
def email_check():
    if request.method == "POST":
        # Query database for email
        rows = db.execute("SELECT * FROM main_table WHERE email = :email",email=request.form.get("email").lower())
        if len(rows) == 0:
            return "true"
        else:
            return "false"

        
        
@app.route("/login", methods=["POST","GET"])
def login():
    if request.method == "POST":
        if request.form.get("username")=="":
            error = "username field cannot be empty"
            return render_template("login.html", error = error)
        if request.form.get("password")=="":
            error = "password field cannot be empty"
            return render_template("login.html", error = error)
        # Query database for username
        rows = db.execute("SELECT * FROM main_table WHERE username = :username",username=str(request.form.get("username")).lower())
        # Remember which user has logged in
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            error = "invalid username/password"
            return render_template("login.html", error = error)
        session["user_id"] = rows[0]["id"]
        if rows[0]["username"] == "admin":
            # select all the schools
            all_schools = db.execute("SELECT * FROM main_table")
            # display them in admin portfolio
            return render_template("admin_page.html", schoolInfo = all_schools)
        # if account is confirmed render this
        if(rows[0]["confirmed"]== "true"):
            tables = database(str(0))
            classRows = db.execute("SELECT * FROM :settings ",settings = tables["settings"])
            # if remember me check box is checked
            if request.form.get("remember_me") == "checked":
                # generate token 
                random_token = random_string_generator(12, string.ascii_letters+string.punctuation)
                # generate series id
                random_series = random_string_generator(12, string.ascii_letters+string.punctuation)
                #set cookie
                resp = make_response(render_template("portfolio.html",schoolInfo = rows, clas = classRows))
                expire_date = datetime.datetime.now()
                expire_date = expire_date + datetime.timedelta(days=90)
                resp.set_cookie("series_id",random_series,expires=expire_date)
                resp.set_cookie("main_token", random_token,expires=expire_date)
                db.execute("UPDATE main_table SET token_id = :series, token = :token WHERE id=:id", series = random_series, token = generate_password_hash(random_token), id=session["user_id"])
                return resp 
                # return render portfolio
            return render_template("portfolio.html", schoolInfo = rows, clas = classRows)
            
        # else if account is not confirmed render unconfirmed view
        else:
            return redirect('/unconfirmed')
    else:
        try:
            session["user_id"]
        except KeyError:
            return render_template("login.html")
        else:
            rows = db.execute("SELECT * FROM main_table WHERE id = :id",id = session["user_id"])
            # if account is confirmed render this
            if(rows[0]["confirmed"]== "true"):
                tables = database(str(0))
                rows = db.execute("SELECT * FROM main_table WHERE id=:id", id = session["user_id"])
                classRows = db.execute("SELECT * FROM :settings ",settings = tables["settings"])
                # return render portfolio
                return render_template("portfolio.html", schoolInfo = rows, clas = classRows)
                
            # else if account is not confirmed render unconfirmed view
            else:
                return redirect('/unconfirmed')


@app.route("/change_password", methods=["POST", "GET"])
def change_password():
    if request.method == "POST":
        # Query database for email
        if request.form.get("email") == "":
            error = "provide the email your account was registered with"
            return render_template("change_password_form.html", error = error)
        rows = db.execute("SELECT * FROM main_table WHERE email = :email",email=request.form.get("email").lower())
        if len(rows) != 1:
            error = request.form.get("email")+" not associated with any registered account"
            return render_template("change_password_form.html", error = error)
        token = generate_confirmation_token(request.form.get("email"))
        confirm_url = url_for('password_changed', token=token, _external=True)
        html = render_template('password.html', confirm_url=confirm_url)
        subject = "change password"
        send_email(request.form.get("email"), subject, html, 'classresultest@gmail.com')
        error = "follow the link sent to "+request.form.get("email") +" to change password"
        return render_template("login.html", error=error)
    else:
        return render_template("change_password_form.html")


@app.route("/password_changed", methods=["GET", "POST"])
def password_changed():
    if request.method == "POST":
        email = request.form.get("email")
        if request.form.get("password") == "":
            error = "password is empty"
            return render_template("password_changed.html", error = error, email = email)
        if len(request.form.get("password")) < 8:
            error = "Make sure your password is at lest 8 letters"
            return render_template("password_changed.html", error = error)

        if request.form.get("confirmation") == "":
            error = "confirmation is empty"
            return render_template("password_changed.html", error = error, email = email)
        if request.form.get("password") != request.form.get("confirmation"):
            error = "password and confirmation do not match"
            return render_template("password_changed", error = error, email = email)
        #change the password
        db.execute("UPDATE main_table SET password = :password WHERE email=:email ",password = generate_password_hash(request.form.get("password")), email = email)
        error = 'You have changed your password.  Thanks!'
        session.clear()
        return render_template('login.html',error=error)
    else:
        token = user = request.args.get('token')
        email = confirm_token(token)
        if  not email:
            error = 'The  link is invalid or has expired.'
            return render_template("login.html", error = error)
        else:
            return render_template("password_changed.html", email = email)


@app.route("/login_check", methods=["POST"])

def login_check():
    if request.method == "POST":
        # Query database for username
        rows = db.execute("SELECT * FROM main_table WHERE username = :username",username=request.form.get("username").lower())
        # Remember which user has logged in
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return "fail"
        else:
            return jsonify({"username": request.form.get("username"), "password": request.form.get("password")})

@app.route("/email_ajax", methods=["POST"])
def email_ajax():
    if request.method == "POST":
        # Query database for username
        rows = db.execute("SELECT * FROM main_table WHERE email = :email",email=request.form.get("email"))
        # Remember which user has logged in
        # Ensure username exists and password is correct
        if len(rows) < 1:
            return "fail"
        else:
            return "pass"

@app.route("/class_name", methods=["POST"])
def class_name():
    if request.method == "POST":
        tables = database(str(0))
        # Query database for username
        rows = db.execute("SELECT * FROM :settings WHERE classname = :classname",settings=tables["settings"],classname=request.form.get("classname").lower())
        if len(rows) == 0:
            return "pass"
        else:
            return "fail"



@app.route("/createClass", methods=["GET", "POST"])
@login_required
def createClass():
    tables = database(str(0))
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
        # Ensure schoolname was submitted
        if not request.form.get("class_name"):
            error = "Provide a class name"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        row = db.execute("SELECT * FROM :settings WHERE classname = :class_name",settings=tables["settings"], class_name = request.form.get("class_name").lower() )
        if len(row) > 0:
            error = "class already exist"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("section"):
            error = "Provide your section"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("firstname"):
            error = "Provide your firstname"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("surname"):
            error = "Provide your surname"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("no_of_students"):
            error = "Provide the number of students in class"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        try:
            val = int(request.form.get("no_of_students"))
        except ValueError:
            error = "Provide a number for the students in class"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("ca"):
            error = "Provide the maximum ca score"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("test"):
            error = "Provide the maximum test score"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        if not request.form.get("exam"):
            error = "Provide the maximum exam score"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        try:
            val = int(request.form.get("ca"))
        except ValueError:
            error = "Provide a number for the class maximum ca"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        try:
            val = int(request.form.get("test"))
        except ValueError:
            error = "Provide a number for the class maximum test"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        try:
            val = int(request.form.get("exam"))
        except ValueError:
            error = "Provide a number for the class maximum exam"
            return render_template("createClassForm.html", error=error, schoolInfo=schoolrow)
        sum = int(request.form.get("ca"))+int(request.form.get("exam"))+int(request.form.get("test"))
        if sum != 100:
            error = "ca + exam + test must be equal to 100"
            return render_template("createClassForm.html", error=error)
        if not request.form.get("password"):
            error = "Provide a class password"
            return render_template("createClassForm.html", error=error)
        if not request.form.get("confirmation"):
            error = "Provide a password confirmation"
            return render_template("createClassForm.html", error=error)
        # Ensure password and confirmation match
        if (request.form.get("password") != request.form.get("confirmation")):
            error = "Provide a password is not equal to  confirmation"
            return render_template("createClassForm.html", error=error)
        info["surname"] = request.form.get("surname")
        info["firstname"] = request.form.get("firstname")
        info["othername"] = request.form.get("othername")
        info["className"] = request.form.get("class_name").upper()
        info["ca_max"] = request.form.get("ca")
        info["test_max"] = request.form.get("test")
        info["exam_max"] = request.form.get("exam")
        info["noOfStudents"] = request.form.get("no_of_students")
        info["password"] = request.form.get("password")
        info["section"] = request.form.get("section")
        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
        return render_template("classListForm.html",n = int(request.form.get("no_of_students")), schoolInfo = schoolrow ) 
    else:
        schoolId = session['user_id']
        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = schoolId)
        return render_template("createClassForm.html",schoolInfo = schoolrow)
        
        
        
@app.route("/classCreated", methods=["POST"])
@login_required
def classCreated():
    tables = database(str(0))
    rows = db.execute("SELECT * FROM main_table WHERE id = :school_id",school_id=session["user_id"])
    schoolClass = tables["classes"]
    identity = info["className"]+"_"+str(datetime.datetime.now())
    #insert class and identifer
    db.execute("INSERT INTO :classes (identifier) VALUES (:name_date)", classes = tables["classes"], name_date = identity)
    #select class id with the identifier
    classRow = db.execute("SELECT * FROM :classes WHERE identifier = :name_d",classes = tables["classes"], name_d = identity)
    classId = classRow[0]["id"]
    session_term =str(rows[0]["current_session"])+"_"+str(rows[0]["current_term"])
    db.execute("INSERT INTO :sessions (id,:current_term) VALUES(:id, :term)", sessions = tables["sessions"], current_term = session_term,id = classId, term = session_term)
    db.execute("INSERT INTO :settings (id,surname,firstname,othername, classname, password,section,ca, test, exam) values (:id,:surname,:firstname,:othername,:className,:password,:section,:ca,:test,:exam)",settings = tables["settings"],id = classId, surname =  info["surname"],firstname =  info["firstname"],othername =  info["othername"], className = info["className"].lower(),password = generate_password_hash(info["password"]),section=info["section"],ca=info["ca_max"], test=info["test_max"], exam=info["exam_max"])
    term_tables(classId)
    tables = database(classId)
    sort_names = []
    # fill classlist
    g = int(info["noOfStudents"])
    for i in range(g):
        surname = "s"+str(i)
        firstname = "f"+str(i)
        othername = "o"+str(i)
        sex = "g"+str(i)
        print(request.form.get(surname))
        sort_names.append((request.form.get(surname), request.form.get(firstname), request.form.get(othername), request.form.get(sex)))
    sort_names = sorted(sort_names, key=itemgetter(0))
    for name in sort_names:
                db.execute("INSERT INTO :classtable (surname, firstname, othername,sex) VALUES (:surname, :firstname, :othername,:sex) ",classtable = tables["classlist"], surname = name[0].upper(),firstname = name[1].upper(),othername = name[2].upper(),sex=name[3])
                db.execute("INSERT INTO :catable DEFAULT VALUES ",catable = tables["ca"])
                db.execute("INSERT INTO :testtable DEFAULT VALUES ",testtable = tables["test"])
                db.execute("INSERT INTO :examtable DEFAULT VALUES ",examtable = tables["exam"])
                db.execute("INSERT INTO :mastersheet DEFAULT VALUES ",mastersheet = tables["mastersheet"])
                db.execute("INSERT INTO :subject_position DEFAULT VALUES ",subject_position = tables["subject_position"])
                db.execute("INSERT INTO :result_data DEFAULT VALUES ",result_data = tables["result"])
    classRows = db.execute("SELECT * FROM :settings ",settings = tables["settings"])
    # return classlist.html
    return render_template("portfolio.html", schoolInfo = rows, clas= classRows)

        
@app.route("/how_to_use", methods=["GET"])
def how_to_use():
        try:
            session["user_id"]
        except KeyError:
            return render_template("how_to_use.html")
        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
        return render_template("how_to_use.html", schoolInfo = schoolrow )

@app.route("/about_us", methods=["GET"])
def about_us():
        try:
            session["user_id"]
        except KeyError:
            return render_template("about_us.html")
        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
        return render_template("about_us.html", schoolInfo = schoolrow )

@app.route("/delete_school", methods=["POST"])
@login_required
def delete_school():
    #get school id
    school_id = request.form.get("id")
    session["user_id"] = school_id
    tables = database(str(0))
    #select classes
    classes = db.execute("SELECT * FROM :classes",classes = tables["classes"])
    #for each class in classes
    for klass in classes:
        #select sessions
        sessions_row = db.execute("SELECT * FROM :sessions WHERE id=:id",sessions = tables["sessions"], id = klass["id"])
        if len(sessions_row) > 0:
            #get values
            sessions = sessions_row[0].values()
            #for each term in sessions
            for term in sessions:
                if term != klass["id"] and term: 
                    terms = str(term).split("_")
                    #get term
                    term = terms[1]
                    #get session
                    current_session = terms[0]
                    #change session
                    db.execute("UPDATE main_table SET current_session=:this_session, current_term = :current_term WHERE id=:id", this_session = current_session, current_term = term , id = school_id)
                    #call database
                    tables = database(klass["id"])
                    #call drop term_tables
                    drop_tables(klass["id"])
    # drop settings
    db.execute("DROP TABLE :settings", settings = tables["settings"])
    # drop classes
    db.execute("DROP TABLE :classes", classes = tables["classes"])
    # drop sessions
    db.execute("DROP TABLE :sessions", sessions = tables["sessions"])
    session["user_id"] = 1
    # delete drow from schools
    db.execute("DELETE FROM main_table WHERE id = :schoolid", schoolid = school_id )
    # select all the schools
    all_schools = db.execute("SELECT * FROM main_table")
    # display them in admin portfolio
    return render_template("admin_page.html", schoolInfo = all_schools)

@app.route("/confirm_classlist", methods=["POST"])
@login_required
def confirm_classlist():
    #declare an array of dicts
    all_students = []
    tables = database(str(0))
    rows = db.execute("SELECT * FROM main_table WHERE id = :school_id",school_id=session["user_id"])
    #fill classlist
    g = int(info["noOfStudents"])
    # each student will be an element of the array
    for i in range(g):
        surname = "s"+str(i)
        firstname = "f"+str(i)
        othername = "o"+str(i)
        sex = "g"+str(i)
        all_students.append((request.form.get(surname), request.form.get(firstname), request.form.get(othername), request.form.get(sex)))
    #return classlist.html
    return render_template("confirm_classlist.html",schoolInfo = rows, students= all_students )
    


@app.route("/submit_score", methods =["POST","GET"])	
@login_required
def submit_score(): 
	if request.method == "POST":
	    if not request.form.get("subject_name"):
	        tables = database(str(0))
	        error = " provide the subject name"
	        classes = db.execute("SELECT * FROM :settings", settings = tables["settings"])
	        schoolId = session['user_id']
	        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = schoolId)
	        return render_template("submit_score_form.html",classes = classes, schoolInfo = schoolrow, error = error)
	    if not request.form.get("the_class"):
	        tables = database(str(0))
	        error = "select one class"
	        classes = db.execute("SELECT * FROM :settings", settings = tables["settings"])
	        schoolId = session['user_id']
	        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = schoolId, error = error)
	        return render_template("submit_score_form.html",classes = classes, schoolInfo = schoolrow)
	    if not request.form.get("subject_teacher"):
	        error = "provide your name"
	        tables = database(str(0))
	        classes = db.execute("SELECT * FROM :settings", settings = tables["settings"])
	        schoolId = session['user_id']
	        schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = schoolId)
	        return render_template("submit_score_form.html",classes = classes, schoolInfo = schoolrow, error = error)
	    subject_info["subject"] = request.form.get("subject_name")
	    subject_info["surname"] = request.form.get("surname")
	    subject_info["firstname"] = request.form.get("firstname")
	    subject_info["subject_teacher"] = request.form.get("subject_teacher")
	    class_id= int(request.form.get("the_class"))
	    tables = database(class_id)
	    subject_info["class_id"] = class_id
	    class_row = db.execute("select * from :classid where id = :current_class", classid = tables["classes"], current_class= tables["class_id"])
	    schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
	    session_setting = db.execute("SELECT * FROM :settings WHERE id = :id", settings = tables["settings"], id = tables["class_id"]  )
	    class_names = db.execute("select * from :thelist ORDER BY surname", thelist = tables["classlist"])
	    return render_template("empty_scoresheet.html",schoolInfo = schoolrow, subject_info = subject_info,class_names = class_names ,classinfo = class_row[0], setting = session_setting)
	else:
	    tables = database(str(0))
	    classes = db.execute("SELECT * FROM :settings", settings = tables["settings"])
	    schoolrow = db.execute("SELECT * FROM main_table WHERE id = :schoolId", schoolId = session["user_id"])
	    return render_template("submit_score_form.html",classes = classes, schoolInfo = schoolrow)


	    
@app.route("/submitted", methods=["POST"])
@login_required
def submitted():
	tables = database(request.form.get("button"))
	classes = tables["classes"]
	class_list = tables["classlist"]
	cascore_table = tables["ca"]
	test_table = tables["test"]
	exam_table = tables["exam"]
	subject_position = tables["subject_position"]
	mastersheet = tables["mastersheet"]
	teachers_table = tables["teachers"]
	subject_table = tables["subjects"]
	db.execute("INSERT INTO :subjects (name) VALUES (:subject) ",subjects = subject_table, subject = subject_info["subject"])
	db.execute("INSERT INTO :teachers (surname, firstname, othername, subject) VALUES (:surname, :firstname, :othername, :subject )",teachers = teachers_table, surname = subject_info["surname"],firstname = subject_info["firstname"],othername = subject_info["othername"], subject = subject_info["subject"])
	db.execute("ALTER TABLE :cascore_table ADD COLUMN :subject TEXT ", cascore_table = cascore_table, subject = subject_info["subject"])
	db.execute("ALTER TABLE :test_table ADD COLUMN :subject TEXT ", test_table = test_table, subject = subject_info["subject"])
	db.execute("ALTER TABLE :exam_table ADD COLUMN :subject TEXT ", exam_table = exam_table, subject = subject_info["subject"])
	db.execute("ALTER TABLE :subject_p ADD COLUMN :subject TEXT", subject_p = subject_position, subject = subject_info["subject"])
	db.execute("ALTER TABLE :mastersheet ADD COLUMN :subject TEXT ", mastersheet = mastersheet, subject = subject_info["subject"])
	db.execute("UPDATE :classes SET no_of_subjects = no_of_subjects + 1 WHERE id = :id", classes = classes, id =tables["class_id"])
	class_list_row = db.execute("SELECT * FROM :classlist", classlist = class_list)
	rows = db.execute("SELECT * FROM school WHERE id = :school_id ",school_id = session["user_id"])
	for  student in class_list_row:
	    cascore = "cascore"+ str(student["id"])
	    testscore = "testscore"+str(student["id"])
	    examscore = "examscore"+str(student["id"])
	    ca_score = request.form.get(cascore)
	    test_score = request.form.get(testscore)
	    exam_score = request.form.get(examscore)
	    db.execute("UPDATE :catable SET :subject = :score WHERE id =:id", catable = cascore_table, subject = subject_info["subject"],score =ca_score, id = student["id"])
	    db.execute("UPDATE :testtable SET :subject = :score WHERE id =:id", testtable = test_table, subject = subject_info["subject"],score =test_score, id = student["id"])
	    db.execute("UPDATE :examtable SET :subject = :score WHERE id =:id", examtable = exam_table, subject = subject_info["subject"],score =exam_score, id = student["id"])
	rows = db.execute("SELECT * FROM school WHERE id = :school_id ",school_id = session["user_id"])
	classrows = db.execute("SELECT * FROM :classes ", classes = classes)
	return render_template("portfolio.html", schoolInfo = rows, clas = classrows)

@app.route("/confirm_scoresheet", methods=["POST"])
@login_required
def confirm_scoresheet():
    #declare an array of 
    class_scores = []
    tables = database(subject_info["class_id"])
    rows = db.execute("SELECT * FROM main_table WHERE id = :school_id",school_id=session["user_id"])
    class_list = db.execute("SELECT * FROM :classlist", classlist = tables["classlist"])
    # each student will be an element of the array
    for student  in class_list:
        ca = "cascore"+str(student["id"])
        test = "testscore"+str(student["id"])
        exam = "examscore"+str(student["id"])
        class_scores.append((student["firstname"], student["surname"], request.form.get(ca), request.form.get(test), request.form.get(exam)))
    #return classlist.html
    return render_template("confirm_scoresheet.html",schoolInfo = rows, students=class_scores, class_id = subject_info["class_id"] )
