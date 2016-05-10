from flask import Flask, flash, redirect, request, session, url_for, render_template
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

CHARONLY_REGEX = re.compile(r'^[a-zA-Z]')
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[@#$%])')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app= Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'friend_wall_db')
app.secret_key = "igotasecretkeyforyou"

@app.route('/')
def index():
	return render_template('index.html')

#user should be able to register
@app.route('/register', methods=['POST'])
def register():

	if len(request.form['first_name']) <2 or not CHARONLY_REGEX.match(request.form['first_name']):
		flash("Please enter a valid first name that's two characters or more", 'regmsg ' )
	elif len(request.form['last_name']) <2 or not CHARONLY_REGEX.match(request.form['last_name']):
		flash("Please enter a valid last name that's two characters or more", 'regmsg ' )
	elif len(request.form['email']) <1 or not EMAIL_REGEX.match(request.form['email']):
		flash("Please enter a valid email", 'regmsg ' )
		#check if email already exists in database
	elif mysql.query_db("SELECT * FROM users WHERE email = '" + request.form['email'] + "'") != []:
		flash("account already exists with this email. Please register another email or login",'regmsg ' )
	elif len(request.form['password']) < 8:
		flash("Password must be more than 8 characters", 'regmsg ' )
	elif not  PASSWORD_REGEX.match(request.form['password']):
		flash("Please make sure you password has at least one number and one symbol", 'regmsg ' )
	elif request.form['password'] != request.form['confirm_password']:
		flash("your passwords do not match ", 'regmsg ')

	else: 

		insert_query = "INSERT INTO users (first_name, last_name, email, pass_hash, created_at, updated_at) VALUES (:firstname, :lastname, :email, :pass_hash, NOW(), NOW())"
		insert_data = {
				'firstname': request.form['first_name'],
				'lastname': request.form['last_name'],
				'email' : request.form['email'],
				'pass_hash' :  bcrypt.generate_password_hash(request.form['password'])
			}
		mysql.query_db(insert_query, insert_data)

		#start mySQL select
		user_list_query = "SELECT users.first_name, users.last_name, users.id as user_id FROM users WHERE email = :email"
		user_list = mysql.query_db(user_list_query, insert_data)
		#end sql select

		#get current user
		session['logged_in'] = "Logged in";
		session['logged_user_info'] = {'id': user_list[0]['user_id'], 'first_name': user_list[0]['first_name'], 'last_name': user_list[0]['last_name']}
		return redirect('/wall_update')
	return redirect('/')
#user should be able to login

@app.route('/login', methods=['GET', 'POST'])
def login():
	# print "*" *50
	# print request.form
	# print "*" *50
	email = request.form['email']
	password = request.form['password']
	#query info put into login form

	insert_query = "SELECT * FROM users WHERE email = :email" 
	insert_data = {'email': email}
	user= mysql.query_db(insert_query, insert_data)
	print user

	#check if password is the same as the pass_hashed in db
	try:
		if  bcrypt.check_password_hash(user[0]['pass_hash'], password):
			#login user
			#start sql select 
			user_list_query = "SELECT users.first_name, users.last_name, users.id as user_id FROM users WHERE email = :email"
			user_list = mysql.query_db(user_list_query, insert_data)
			#end sql select

			#get current user
			session['logged_in'] = "Logged in";
			session['logged_user_info'] = {'id': user_list[0]['user_id'], 'first_name': user_list[0]['first_name'], 'last_name': user_list[0]['last_name']}
			return redirect('/wall_update')
			
		else:

			flash("sorry, you entered the wrong password", 'logmsg' )
			return redirect(url_for('login'))
	except IndexError: 
		flash("login error, username or password doesn't match")
		return redirect('/')
		

@app.route('/wall_update')
def wall_update():
	
	#start mySQL select
	postings = mysql.query_db("SELECT concat_ws(' ', users.first_name, users.last_name) as name, messages.id as message_id, messages.message, DATE_FORMAT(messages.created_at, '%M %D %Y') FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC")
	
	comments = mysql.query_db("SELECT  messages.id as message_id, comments.comments, comments.created_at, concat_ws(' ', users.first_name, users.last_name) as 'Message Author', CONCAT( users2.first_name, ' ',users2.last_name ) as 'Comment Authors' FROM messages JOIN users JOIN comments ON comments.message_id = messages.id LEFT JOIN users as users2 ON users2.id = comments.user_id GROUP BY messages.id ORDER BY comments.created_at DESC")
	print comments
	#end select

	return render_template('wall.html', postings = postings, comments =comments)


@app.route('/post_message', methods =['POST'])
def post_message():
	user_id = session['logged_user_info']['id']
	message = request.form['post_message']
	insert_query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:id, :message, NOW(), NOW())"
	insert_data = {
			'id': user_id,
			'message': request.form['post_message']
		}
	mysql.query_db(insert_query, insert_data)

	return redirect('/wall_update')

@app.route('/comments', methods =['POST'])
def post_comment():
	user_id = session['logged_user_info']['id']
	message_id = request.form['message_id']
	comment = request.form['post_comment']
	insert_comment_query = "INSERT INTO comments (user_id, message_id, comments, created_at, updated_at) VALUES (:user_id, :message_id, :comment, NOW(), NOW())"
	insert_comment_data = {
			'user_id': user_id,
			'message_id': message_id,
			'comment': comment
		}
	mysql.query_db(insert_comment_query, insert_comment_data)

	return redirect('/wall_update')



@app.route('/logout', methods=['GET'])
def logout():
	session.clear()

	return render_template('index.html')


app.run(debug=True)








