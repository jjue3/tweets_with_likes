from flask import Flask, render_template, request, redirect, session, flash, url_for
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key = 'secret_key'
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
import re 
email_rex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
name_rex = re.compile(r'^[a-zA-Z]+$')    
password_rex = re.compile(r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]{6,24}$')

@app.route('/') #Renders Login Page
def index():
    return render_template('index.html')    

@app.route('/', methods=['POST']) #Registration page
def registration():
    is_valid = True
    mysql = connectToMySQL('reg')       
    query = 'SELECT * FROM users WHERE email=%(email)s;'
    data = {
        "email" : request.form['email']
    }
    existing_email = mysql.query_db(query, data)
    if len(request.form['first_name']) < 2 or not name_rex.match(request.form['first_name']): #Check to see if first name is long enough or if it has a number
        is_valid = False
        flash("Please enter your first name")
        print('false')
        return redirect('/')
    if len(request.form['last_name']) < 2 or not name_rex.match(request.form['last_name']): #Check to see if last name is long enough or if it has a number
        is_valid = False
        flash("Please enter your last name")
        print('false')
        return redirect('/')
    if not email_rex.match(request.form['email']): #Check if the email has the requirements
        is_valid = False
        flash("Please enter an email")
        print('false')
        return redirect('/')        
    if existing_email: #Check if the email exists in the database
        is_valid = False
        flash("Email already in use")
        print('false')
        return redirect('/')
    if not password_rex.match(request.form['password']): #Checks if passward has more than 6 characters, has symbols @#$, and has a capital
        is_valid = False
        flash("Please enter a password")
        print('false')
        return redirect('/')
    if request.form['password'] != request.form['passwordc']: #Check if the confirmation password matches the entered password
        is_valid = False
        flash("Password does not match")
        print('false')    
        return redirect('/')
    if is_valid: #addes to the database
        flash("Successfully added!")
        password = bcrypt.generate_password_hash(request.form['password'])
        print(password)
        data = {
                "first_name": request.form["first_name"],
                "last_name": request.form["last_name"],
                "email": request.form["email"],
                "password" : password
                }
        mysql = connectToMySQL('reg')         
        query = "INSERT INTO reg.users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW());"
        userlog = mysql.query_db(query, data)
        session['email']= request.form['email']
        session['name'] = request.form['first_name']
        return redirect('/dashboard')

@app.route('/login', methods=['POST'])
def login():
    if len(request.form['email'])<1: #Checks if anything there is anything in the email field
        flash("Please enter email")
        return redirect('/')
    if len(request.form['password'])<1: #Checks if anything there is anything in the password field
        flash("Please enter password")
        return redirect('/')
    mysql = connectToMySQL('reg')       
    query = 'SELECT * FROM users WHERE email=%(email)s;'
    data = {
        "email" : request.form['email']
        }
    query_result = mysql.query_db(query, data)
    if not query_result: #Checks if there is anything in the database   
        flash('Email/Password is incorrect')
        return redirect('/')
    pw_hash = query_result[0]["password"]
    password_check = bcrypt.check_password_hash(pw_hash,request.form['password'])
    if query_result: #Checks if it matches the database
        if password_check:
            session['name'] = query_result[0]["first_name"]
            session['id'] = query_result[0]["id"]
            print(session['name'])
            return redirect('/dashboard')
    else:
        flash("Email/Password is incorrect")
        return redirect('/')

@app.route('/tweets/{tweet_id}/add_like', methods=['POST']) #Add likes
def addlike(tweet_id):
    mysql = connectToMySQL('reg')         
    query = "INSERT INTO likes (user_id, tweet_id, created_at, updated_at) VALUES (%(user_id)s, %(tweet_id)s, NOW(), NOW());"
    data = {
        "user_id" : session['id']
        }
    userlog = mysql.query_db(query, data)
    print('THIS IS WHAT I AM LOOKING FOR!!!!!')
    print(tweet_id) 
    return redirect('/dashboard')      

# @app.route('/tweets/{tweet_id}/delete')
# def delete():
    
#     return redirect('/dashboard')        

@app.route('/logout')
def logout():
    session.clear()
    print(session)
    return redirect('/')         

@app.route('/dashboard') #Displays all messages
def dashboardren(): 
    name = session['name']
    mysql = connectToMySQL('reg')       
    tweets = mysql.query_db('SELECT * FROM tweets ORDER BY id DESC;')
    print(tweets)
    return render_template('dashboard.html', tweets = tweets, name = name)

@app.route('/tweets/create', methods=['POST']) #Creates and posts messages in the database
def createpost():
    if len(request.form['message'])>255 or len(request.form['message'])<1:
        flash('Invalid amount of characters')
        return redirect('/dashboard')
    else:    
        mysql = connectToMySQL('reg')       
        query = "INSERT INTO tweets (content, user_id, created_at) VALUES (%(content)s, %(user_id)s, NOW());"
        data = {
            "content" : request.form["message"],
            "user_id" : session['id']
            }
        mysql.query_db(query, data)
        print(session['id'])
        print(request.form['message'])
        flash('Posted!')
        return redirect('/dashboard')

@app.route('/users') #renders all users page
def userslist():
    name = session['name']
    mysql = connectToMySQL('reg') 
    users = mysql.query_db('SELECT * From users')
    return render_template('users.html', users = users, name = name)    

@app.route('/dashboard')
def arelogged():        
    if not session['name']:
        return redirect('/')
    else:    
        return redirect('/dashboard')
    
if __name__ == "__main__":
    app.run(debug=True)
