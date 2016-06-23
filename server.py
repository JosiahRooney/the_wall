import os
from flask import Flask, request, redirect, render_template, session, flash, url_for, send_from_directory
from mysql import MySQLConnector
import timeago
import datetime
from dateutil import parser
from werkzeug.utils import secure_filename

import re
from flask_bcrypt import Bcrypt

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif']

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'frogo')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.secret_key = "983248gdssd923w2198321e1348g92d"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
PW_REGEX = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$')
login_msg = "You must be logged in to view this page."

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def is_logged_in():
    return True if session['user_logged_in'] else False


@app.route('/')
def index():
    if 'tried_url' in session:
        session.pop('tried_url')
    if "user_logged_in" not in session:
        session['user_logged_in'] = False
    if "user_level" not in session:
        session['user_level'] = False
    print(session['user_level'])
    return render_template('index.html')


@app.route('/login/')
def login_process():
    return render_template('login.html')


@app.route('/login/process', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    errors = False
    query_data = {
        'username': username
    }

    if len(username) == 0:
        flash("Please enter your username", 'username_error')
        errors = True
    else:
        query_data['username'] = username

    if len(password) == 0:
        flash("Please enter your password", 'password_error')
        errors = True

    if errors:
        return redirect('/login')
    else:
        select_query = "SELECT * FROM users WHERE username = :username LIMIT 1"
        user = mysql.query_db(select_query, query_data)
        if user:
            if bcrypt.check_password_hash(user[0]['pw_hash'], password):
                if user[0]['user_banned'] == '1':
                    flash("Your account is suspended for account action. If you believe this is in error, "
                          "contact an administrator.", "error")
                    return redirect('/')
                flash("Logged in!", 'success')
                session['user_logged_in'] = True
                session['username'] = username
                select_query = "SELECT user_id, user_image, level FROM users WHERE username = :username"
                data = {"username": username}
                result = mysql.query_db(select_query, data)
                session['user_id'] = result[0]['user_id']
                session['user_image'] = result[0]['user_image']
                session['user_level'] = result[0]['level']
                if "tried_url" in session:
                    return redirect(session['tried_url'])
                else:
                    return redirect('/posts/')
        flash("The username or password didn't seem to work, please try again.", 'error')
        return redirect('/login')


@app.route('/wall')
def wall():
    if session['user_logged_in']:
        return redirect('/wall/'+str(session['user_id']))
    else:
        flash(login_msg, 'error')
        session['tried_url'] = '/wall'
        return redirect('/login')


@app.route('/wall/<user_id>')
def wall_user(user_id):
    if session['user_logged_in']:
        if str(session['user_id']) == str(user_id):
            query = "SELECT * FROM posts WHERE user_id = :user_id"
            data = {"user_id": user_id}
            posts = mysql.query_db(query, data)
            return render_template('wall.html', posts=posts)
        else:
            return redirect('/wall/'+str(session['user_id']))
    else:
        flash(login_msg, 'error')
        session['tried_url'] = '/wall/'+str(user_id)
        return redirect('/login')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out", 'success')
    return redirect('/')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register/process', methods=['POST'])
def register_process():
    email = request.form['email']
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    query_data = {
        'username': username,
        'email': email,
        'pw_hash': ''
    }
    errors = False

    if len(email) == 0:
        flash('Please enter your email', 'error')
        print("You didn't enter an email")
        errors = True

    if len(username) == 0:
        flash('Please enter a username', 'error')
        print("You didn't enter a username")
        errors = True

    if len(password) < 8:
        flash('Please enter a password of at least 8 characters', 'error')
        print("Password isnt long enough")
        errors = True
    else:
        if password == confirm_password:
            if PW_REGEX.match(password):
                pw_hash = bcrypt.generate_password_hash(password)
                query_data['pw_hash'] = pw_hash
            else:
                flash("Please use at least one lowercase letter, one uppercase letter, and one special character"
                      " in your password", 'error')
                print("Your password didn't meet the criteria")
                errors = True
        else:
            flash("Please enter the same password twice", 'error')
            print("Password didn't match")
            errors = True

    if errors:
        print('There were errors')
        return redirect('/register')
    else:
        insert_query = "INSERT INTO users (username, pw_hash, email, created_at, updated_at) VALUES (:username," \
                       " :pw_hash, :email, NOW(), NOW())"
        mysql.query_db(insert_query, query_data)
        flash('Account successfully created!', 'success')
        session['user_logged_in'] = True
        select_query = "SELECT user_id FROM users WHERE username = :username"
        data = {"username": username}
        result = mysql.query_db(select_query, data)
        session['user_id'] = result[0]['user_id']
        return redirect('/wall')


@app.route('/posts/')
def show_all_posts():

    if not session['user_logged_in']:
        flash(login_msg, "error")
        return redirect('/login/')

    query = "SELECT posts.post_id, posts.post_content, posts.created_at AS 'posted_date', posts.created_at AS " \
            "'posted_date_readable', posts.user_id AS 'post_user_id', users.user_id AS 'user_user_id', " \
            "users.username, users.user_image FROM posts JOIN users on users.user_id = posts.user_id ORDER BY" \
            " posts.created_at DESC"
    posts = mysql.query_db(query)
    for post in posts:
        now = datetime.datetime.now()
        post['posted_date'] = timeago.format(post['posted_date'], now)
        post['posted_date_readable'] = datetime.datetime.strftime(post['posted_date_readable'], "%A, %B %d, "
                                                                                                "%Y %H:%M:%S")

        query = "SELECT users.username, users.user_image, users.user_id, comments.created_at, " \
                "comments.comment_content FROM comments JOIN users on users.user_id = comments.user_id " \
                "WHERE post_id = :post_id"
        data = {"post_id": post['post_id']}
        post['post_comments'] = mysql.query_db(query, data)

        for comment in post['post_comments']:
            comment['created_at'] = parser.parse(comment['created_at'])
            comment['created_at_readable'] = datetime.datetime.strftime(comment['created_at'], "%A, %B %d, %Y %H:%M:%S")
            comment['created_at'] = timeago.format(comment['created_at'], now)

    return render_template('posts.html', posts=posts)


@app.route('/posts/new/')
def new_post():
    if is_logged_in():
        return render_template('add.html')
    else:
        flash(login_msg, 'error')
        session['tried_url'] = '/posts/new'
        return redirect('/login')


@app.route('/posts/add', methods=['POST'])
def add_post():
    content = request.form['post_content']
    if len(content) == 0:
        print("Error in post")
        flash('You must enter something here', 'error')
        return redirect('/posts/new')
    else:
        query = "INSERT INTO posts (post_content, created_at, updated_at, user_id) VALUES (:content, NOW(), NOW()," \
                " :user_id)"
        data = {
            'content': content,
            'user_id': session['user_id']
        }
        mysql.query_db(query, data)
        query = "SELECT LAST_INSERT_ID();"
        last_id = mysql.query_db(query)[0]['LAST_INSERT_ID()']
        print(last_id)
        return redirect('/posts/#post_id_'+str(last_id))


@app.route('/post/<post_id>/')
def show_post(post_id):
    query = "SELECT * FROM posts WHERE post_id = :post_id LIMIT 1"
    data = {"post_id": post_id}
    this_post = mysql.query_db(query, data)
    user_id = this_post[0]['user_id']
    query = "SELECT * FROM users WHERE user_id = :user_id LIMIT 1"
    data = {"user_id": user_id}
    post_author = mysql.query_db(query, data)
    query = "SELECT * FROM comments JOIN users on users.user_id = comments.user_id WHERE post_id = :post_id"
    data = {"post_id": post_id}
    post_comments = mysql.query_db(query, data)
    if this_post:
        print("There is a post!")
        return render_template('post.html', this_post=this_post, post_author=post_author, post_comments=post_comments)
    else:
        flash('There is no post with the ID of '+str(post_id))
        return render_template('post.html')


@app.route('/post/<post_id>/comment/new', methods=['POST'])
def new_post_comment(post_id):
    comment = request.form['comment_content']
    if len(comment) == 0:
        flash("Please enter a comment", 'error')
        return redirect('/post/'+str(post_id))
    else:
        query = "INSERT INTO comments (comment_content, created_at, updated_at, user_id, post_id) VALUES " \
                "(:comment_content, NOW(), NOW(), :user_id, :post_id)"
        data = {
            "comment_content": comment,
            "user_id": session['user_id'],
            "post_id": post_id
        }
        mysql.query_db(query, data)
        return redirect('/posts/#post_id_'+str(post_id))


@app.route('/users/')
def all_users():
    query = "SELECT * FROM users ORDER BY username ASC"
    users = mysql.query_db(query)
    return render_template('users.html', users=users)


@app.route('/user/<user_id>/')
def show_user(user_id):
    query = "SELECT * FROM users WHERE user_id = :user_id LIMIT 1"
    data = {"user_id": user_id}
    users = mysql.query_db(query, data)
    if not users:
        flash("There is no user with the ID of "+str(user_id), 'error')
        return render_template('user.html')
    else:
        return render_template('user.html', user=users[0])


@app.route('/upload/<source>', methods=['POST'])
def upload(source):
    # Get the name of the uploaded file
    newfile = request.files['file']
    # Check if the file is one of the allowed types/extensions
    if newfile and allowed_file(newfile.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(newfile.filename)
        # Move the file form the temporal folder to
        # the upload folder we setup
        newfile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Redirect the user to the uploaded_file route, which
        # will basicaly show on the browser the uploaded file

        if source == "user_page":
            # file was uploaded from user profile
            query = "UPDATE users SET user_image = :user_image WHERE user_id = :user_id"
            data = {
                "user_image": url_for('uploaded_file', filename=filename),
                "user_id": session['user_id']
            }
            mysql.query_db(query, data)
            session['user_image'] = url_for('uploaded_file', filename=filename)
            flash("Profile picture successfully updated!", "success")
            return redirect('/user/'+str(session['user_id']))
        return redirect(url_for('uploaded_file', filename=filename))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/post/<post_id>/delete/')
def delete_post(post_id):
    query = "SELECT * FROM posts WHERE post_id = :post_id"
    data = {"post_id": post_id}
    result = mysql.query_db(query, data)
    if result:
        query = "DELETE FROM comments WHERE post_id = :post_id"
        mysql.query_db(query, data)
        query = "DELETE FROM posts WHERE post_id = :post_id"
        mysql.query_db(query, data)
        flash("Post deleted", "success")
        return redirect('/posts')
    flash("There is no post with the ID of "+str(post_id), "error")
    return redirect('/posts/')


@app.route('/user/<user_id>/ban/')
def ban_user(user_id):
    query = "SELECT * FROM users WHERE user_id = :user_id"
    data = {"user_id": user_id}
    users = mysql.query_db(query, data)
    if users:
        query = "UPDATE users SET user_banned=:user_banned, updated_at=NOW() WHERE user_id = :user_id"
        data = {"user_id": user_id, "user_banned": True}
        mysql.query_db(query, data)
        flash("User: "+users[0]['username']+" banned.", "success")
        return redirect('/user/'+str(user_id)+'/')


@app.route('/user/<user_id>/unban/')
def unban_user(user_id):
    query = "SELECT * FROM users WHERE user_id = :user_id"
    data = {"user_id": user_id}
    users = mysql.query_db(query, data)
    if users:
        query = "UPDATE users SET user_banned=:user_banned, updated_at=NOW() WHERE user_id = :user_id"
        data = {"user_id": user_id, "user_banned": False}
        mysql.query_db(query, data)
        flash("User: "+users[0]['username']+" unbanned.", "success")
        return redirect('/user/'+str(user_id)+'/')


@app.errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', request.path)
    return render_template('404.html'), 4044


app.run(debug=True)
