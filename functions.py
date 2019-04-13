import requests
from cs50 import SQL
from flask import redirect, render_template, request, session
from functools import wraps
from operator import itemgetter, attrgetter
from itsdangerous import URLSafeTimedSerializer
import random
import string

from flask_mail import Message, Mail


# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = "classresultest@gmail.com"
MAIL_PASSWORD = "classresultvenuse123"

# mail accounts
MAIL_DEFAULT_SENDER = 'classresult'


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///schools.db")

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


#def check_confirmed(func):
  #  @wraps(func)
   # def decorated_function(*args, **kwargs):
      #  if current_user.confirmed is False:
       #     flash('Please confirm your account!', 'warning')
        #    return redirect(url_for('user.unconfirmed'))
       # return func(*args, **kwargs)

   # return decorated_function



# gives the initial of a name
def initials (name):
    return name[0].upper()
# returns the grade of any given score
def grade(score):
	grading_type="WAEC"
	score = int(score)
	if grading_type == "WAEC":
		if score < 40:
			score_grade = "F"
		elif score > 39 and score < 46:
			score_grade = "E"
		elif score > 44 and score < 51:
			score_grade = "D"
		elif score > 49 and score < 61:
			score_grade = "C"
		elif score > 59 and score < 75:
			score_grade = "B"
		else:
			score_grade = "A"
	else:
		if score < 29:
			score_grade = "F"
		elif score > 29 and score < 40:
			score_grade = "E"
		elif score > 39 and score < 50:
			score_grade = "D"
		elif score > 49 and score < 60:
			score_grade = "C"
		elif score > 59 and score < 70:
			score_grade = "B"
		else:
			score_grade = "A"

	return score_grade

# forms the result data given the id of the class
def database(id):
    tables = {}
    # format class tables names
    school = db.execute("SELECT * FROM main_table WHERE id=:id", id=session["user_id"])
    current_session = school[0]["current_session"]
    current_term = school[0]["current_term"]
    tables["settings"] = "settings"+"_"+str(session["user_id"])+"_"+current_session
    tables["class_id"] = id
    tables["school_id"] = session["user_id"]
    schoolId = session["user_id"]
    tables["classes"] = "classes"+"_"+str(tables["school_id"])
    tables["sessions"] = "sessions"+"_"+str(tables["school_id"])
    tables["classlist"] = "classlist"+"_"+str(tables["class_id"])+"_"+str(tables["school_id"])
    classIdentifier = str(tables["class_id"])+"_"+str(current_term)+"_"+str(current_session)+"_"+str(tables["school_id"])
    tables["ca"]  = "catable"+"_"+classIdentifier
    tables["test"] = "testtable"+"_"+classIdentifier
    tables["exam"] = "examtable"+"_"+classIdentifier
    tables["subjects"] = "subjects"+"_"+classIdentifier
    tables["mastersheet"] = "mastersheet"+"_"+classIdentifier
    tables["subject_position"] = "subject_position"+"_"+classIdentifier
    tables["grade"] = "grade"+"_"+classIdentifier
    tables["result"] = "result"+"_"+str(current_term)+"_"+str(current_session)+"_"+str(tables["school_id"])
    return tables
# makes the result of a single student given class and student id
def make_student_result(student_id, class_id):
	tables = database(class_id)
	student = db.execute("SELECT * FROM :classlist WHERE id=:id", classlist = tables["classlist"], id=student_id)
	student = student[0]
	classroom = db.execute("SELECT * FROM :classes WHERE id=:class_id", classes = tables["classes"], class_id = class_id)
	subjects = db.execute("SELECT * FROM :subject", subject = tables["subjects"])
	no_0f_subjects = classroom[0]["no_of_subjects"]
	total_score = 0
	student_average = 0
	for subject in subjects:
		sub_total =  db.execute("SELECT * FROM :mastersheet WHERE id=:id ",mastersheet = tables["mastersheet"], id = student_id)
		sub_total = int(sub_total[str(subject['id'])])
		if sub_total:
			sub_grade = grade(sub_total)
			db.execute("UPDATE :grade SET :subject =:sub_grade WHERE id = :id ", grade = tables["grade"], subject = str(subject["id"]), sub_grade = sub_total, id = student_id)

			if sub_grade ==  "A":
				#increase no of A for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_A",  id = student_id)
			elif sub_grade ==  "B":
				#increase no of B for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_B",  id = student_id)

			elif sub_grade ==  "C":
				#increase no of C for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_C",  id = student_id)

			elif sub_grade ==  "D":
				#increase no of D for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_D",  id = student_id)

			elif sub_grade ==  "E":
				#increase no of E for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_E",  id = student_id)

			else:
				#increase no of F for student
				db.execute("UPDATE :grade SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", grade = tables["grade"], no_of_grade = "no_of_F",  id = student_id)

			if sub_total > 39:
				db.execute("UPDATE :subjects SET no_students_passed = no_students_passed + 1 WHERE id = :id ", subjects = tables["subjects"],  id = subject['id'])
				db.execute("UPDATE :mastersheet SET no_subjects_passed = no_subjects_passed + 1 WHERE id = :id ", mastersheet = tables["mastersheet"],  id = student_id)
			else:
				db.execute("UPDATE :subjects SET no_students_failed = no_students_failed + 1 WHERE id = :id ", subjects = tables["subjects"],  id = subject['id'])
				db.execute("UPDATE :mastersheet SET no_subjects_failed = no_subjects_failed + 1 WHERE id = :id ", mastersheet = tables["mastersheet"],  id = student_id)

		total_score = total_score + sub_total
	db.execute("UPDATE :mastersheet SET total_score = :total_score WHERE id = :id  ", mastersheet = tables["mastersheet"], total_score = total_score, id = student_id)
	student_average = total_score / classroom[0]["no_of_subjects"]
	db.execute("UPDATE :mastersheet SET average = :student_average WHERE id = :id  ", mastersheet = tables["mastersheet"], student_average = student_average, id = student_id)
	if student_average > 39:
		db.execute("UPDATE :result_data SET no_students_passed = no_students_passed + 1 WHERE id = :id ", result_data = tables["result"],  id = class_id)
	else:
		db.execute("UPDATE :result_data SET no_students_failed = no_students_failed + 1 WHERE id = :id ", classes = tables["result"],  id = class_id)




def make_subject_result(subject_id, class_id):
    tables = database(class_id)
    subject_col = str(subject_id)
    mastersheet_data = db.execute("SELECT * FROM :mastersheet", mastersheet = tables["mastersheet"])
    subject = db.execute("SELECT * FROM :subjects WHERE id=:id", subjects = tables["subjects"], id = subject_id)
    classroom = db.execute("SELECT * FROM :classes WHERE id = :class_id", classes = tables["classes"], class_id= tables["class_id"])
    subject_total = 0
    exam_row = db.execute("SELECT * FROM :exam", exam = tables["exam"])
    i = 0
    for student in mastersheet_data:
    	if exam_row[i][subject_col]:
    		total = db.execute("SELECT * FROM :mastersheet WHERE id=:id", mastersheet = tables["mastersheet"], id = student["id"])
    		total = total[0][subject_col]
    		sub_grade = grade(total)
    		if total < 40:
    			db.execute("UPDATE :subject SET no_of_fails = no_of_fails + 1", subject = tables["subjects"])
    		else:
    			db.execute("UPDATE :subject SET no_of_pass = no_of_pass + 1", subject = tables["subjects"])
    		if sub_grade ==  "A":
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_A",  id = subject_id)
    		elif sub_grade ==  "B":
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_B",  id = subject_id)
    		elif sub_grade ==  "C":
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_C",  id = subject_id)
    		elif sub_grade ==  "D":
    			#increase no of D for student
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_D",  id = subject_id)
    		elif sub_grade ==  "E":
    			#increase no of E for student
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_E",  id = subject_id)
    		elif sub_grade ==  "F":
    			db.execute("UPDATE :subject SET :no_of_grade =:no_of_grade + 1 WHERE id = :id ", subject = tables["subjects"], no_of_grade = "no_of_F",  id = subject_id)
    		i = i + 1
    subject_row = db.execute("SELECT * FROM :subject WHERE id = :id", subject = tables["subjects"], id = subject_id)
    no_of_fails = int(subject_row["no_of_fails"])
    no_of_pass = int(subject_row["no_of_pass"])
    no_of_students_present = no_of_fails + no_of_pass
    fails_percent = (no_of_fails/no_of_students_present) * 100
    pass_percent = (no_of_pass/no_of_students_present) * 100
    db.execute("UPDATE :subject SET fails_percent = :fails_percent, pass_percent = :pass_percent WHERE id=:id ", subject=["subjects"], fails_percent = fails_percent, pass_percent = pass_percent, id = subject_id)
    subject_average = subject_total / classroom[0]["no_of_students"]
    db.execute("UPDATE :subjects SET class_average = :average WHERE id = :id", subjects = tables["subjects"],  average = subject_average, id = subject_id )

def render_class(class_id, error):
    tables = database(class_id)
    classrow = db.execute("SELECT * FROM :classes WHERE id = :classId", classes = tables["classes"], classId = tables["class_id"])
    schoolrow = db.execute("SELECT * FROM school WHERE id = :schoolId", schoolId = tables["school_id"])
    carow = db.execute("SELECT * FROM :catable",catable = tables["ca"])
    testrow = db.execute("SELECT * FROM :testtable",testtable = tables["test"])
    examrow = db.execute("SELECT * FROM :examtable",examtable = tables["exam"])
    subjectrow = db.execute("SELECT * FROM :subjecttable",subjecttable = tables["subjects"])
    teachersrow = db.execute("SELECT * FROM :teacherstable", teacherstable= tables["teachers"])
    classlistrow = db.execute("SELECT * FROM :classlist",classlist = tables["classlist"])
    mastersheet_rows = db.execute("SELECT * FROM :mastersheet", mastersheet = tables["mastersheet"])
    subject_position_row = db.execute("SELECT * FROM :subject_position", subject_position = tables["subject_position"])
    return render_template("classView.html",error = tables["error"],  schoolInfo = schoolrow, classData = classrow, caData = carow, testData = testrow, examData = examrow, subjectData = subjectrow, teachersData = teachersrow,class_list = classlistrow, mastersheet = mastersheet_rows, subject_position = subject_position_row)

def render_portfolio(school_id, error):
    tables = database(0)
    rows = db.execute("SELECT * FROM main_table WHERE id = :school_id ",school_id = session["user_id"])
    classrows = db.execute("SELECT * FROM :settings ", classes = tables["settings"])
    return render_template("portfolio.html",error = error, schoolInfo = rows, classData = classrows)

def assign_student_position(class_id):
	tables = database(class_id)
	student_position  = db.execute("SELECT * FROM :mastersheet", mastersheet = tables["mastersheet"])
	student_position = sorted(student_position, key = itemgetter('average'), reverse=True)
	j = 0
	i = 0
	previous = 101
	for person in student_position:
		if previous == person["average"]:
			db.execute("UPDATE :mastersheet SET position = :sposition  WHERE id =:id", mastersheet = tables["mastersheet"],  sposition = j, id = person["id"])
		else:
			j = i + 1
			db.execute("UPDATE :mastersheet SET position = :sposition  WHERE id =:id", mastersheet = tables["mastersheet"],  sposition = j, id = person["id"])
		i = i + 1
		previous = person["average"]


def assign_subject_position(class_id, subject_id):
	tables = database(class_id)
	subject = str(subject_id)
	subject_position  = db.execute("SELECT * FROM :mastersheet",  mastersheet = tables["mastersheet"])
	subject_position = sorted(subject_position, key = itemgetter(subject), reverse=True)

	j = 0
	i = 0
	previous = 101
	for person in subject_position:
		if previous == person[subject]:
			db.execute("UPDATE :positIon_table SET :subject = :position    WHERE id =:id", positIon_table = tables["subject_position"],subject = subject,  position = j, id = person["id"])
		else:
			j = i + 1
			db.execute("UPDATE :positIon_table SET :subject = :position    WHERE id =:id", positIon_table = tables["subject_position"],subject = subject,  position = j, id = person["id"])
		i = i + 1
		previous = person[subject]

def update_scores(class_id, subject_id, operation):
	tables = database(subject_id)
	subject = str(subject_id)
	mastersheet_scores = db.execute("SELECT * FROM :mastersheet", mastersheet = tables["mastersheet"] )
	classrow = db.execute("SELECT * FROM :classes WHERE id=:class_id", classes = tables["classes"], class_id = class_id )
	for student in mastersheet_scores:
		if operation == "ADD":
			total = student["total"] + student["subject"]
		else:
			total = student["total"] - student["subject"]

		average = total / classrow[0]["no_of_subjects"]
		db.execute("UPDATE :mastersheet SET total = :total, average = :average WHERE id=:id", mastersheet = tables["mastersheet"], total = total, average = average, id = student["id"])




def random_string_generator(str_size, allowed_chars):
    return ''.join(random.choice(allowed_chars) for x in range(str_size))

def term_tables(classid):
	tables = database(classid)
	db.execute("CREATE TABLE :classlist ('id' INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL, 'surname' TEXT,'firstname' TEXT,'othername' TEXT,'sex' TEXT, 'pin' TEXT)",classlist = tables["classlist"] )

	db.execute("CREATE TABLE :classsubjects ('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'name' TEXT, 'total_score' INTEGER DEFAULT 0,'ppass' INTEGER DEFAULT 0,'class_average' INTEGER DEFAULT 0,'no_of_A' INTEGER DEFAULT 0, no_of_B INTEGER DEFAULT 0, no_of_C INTEGER DEFAULT 0,no_of_D INTEGER DEFAULT 0,no_of_E INTEGER DEFAULT 0,no_of_F INTEGER DEFAULT 0)",classsubjects = tables["subjects"] )

	# create  catable
	db.execute("CREATE TABLE :catable ('id' INTEGER PRIMARY KEY   NOT NULL)",catable = tables["ca"] )

	# create  grade
	db.execute("CREATE TABLE :grade ('id' INTEGER PRIMARY KEY   NOT NULL, 'no_of_A' INTEGER DEFAULT 0,'no_of_B' INTEGER DEFAULT 0,'no_of_C' INTEGER DEFAULT 0,'no_of_D' INTEGER DEFAULT 0,'no_of_E' INTEGER DEFAULT 0,'no_of_F' INTEGER DEFAULT 0)",grade = tables["grade"] )

	# create testtable
	db.execute("CREATE TABLE :testtable ('id' INTEGER PRIMARY KEY   NOT NULL)",testtable = tables["test"] )

	# create examtable
	db.execute("CREATE TABLE :examtable ('id' INTEGER PRIMARY KEY  NOT NULL)",examtable = tables["exam"] )

	# create mastersheet
	db.execute("CREATE TABLE :mastersheet ('id' INTEGER PRIMARY KEY  NOT NULL, 'total_score' INTEGER DEFAULT 0, 'average' INTEGER DEFAULT 0, 'passed' INTEGER DEFAULT 0, 'position' INTEGER )",mastersheet = tables["mastersheet"] )

	# create subject_position
	db.execute("CREATE TABLE :subjectposition ('id' INTEGER PRIMARY KEY  NOT NULL)",subjectposition = tables['subject_position'] )


def drop_tables(classid):
	tables = database(classid)

	db.execute("DROP TABLE :classsubjects ",classsubjects = tables["subjects"] )

	# create  catable
	db.execute("DROP TABLE :catable",catable = tables["ca"] )

	# create  grade
	db.execute("DROP TABLE :grade",grade = tables["grade"] )

	# create testtable
	db.execute("DROP TABLE :testtable",testtable = tables["test"] )

	# create examtable
	db.execute("DROP TABLE :examtable ",examtable = tables["exam"] )

	# create mastersheet
	db.execute("DROP TABLE :mastersheet",mastersheet = tables["mastersheet"] )

	# create subject_position
	db.execute("DROP TABLE :subjectposition",subjectposition = tables['subject_position'] )

	db.execute("DROP TABLE :classlist ",classlist = tables["classlist"] )

