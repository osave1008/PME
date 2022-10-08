import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db, close_db #Eduardo

bp = Blueprint('auth', __name__, url_prefix='/auth')

def send_email(credentials, receiver, subject, message): #Eduardo
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp.office365.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': #Eduardo
            number = request.args['auth'] 
            
            db = get_db() #Eduardo
            attempt = db.execute(
                'SELECT * FROM activationlink WHERE CHALLENGE = ? AND STATE = ?', (number, utils.U_UNCONFIRMED) #Eduardo
            ).fetchone()

            if attempt is not None:
                db.execute(
                    'UPDATE activationlink SET STATE = ? WHERE ID = ?', (utils.U_CONFIRMED, attempt['id']) #Eduardo
                )
                db.execute(
                    'INSERT INTO USER (USERNAME, PASSWORD, SALT, EMAIL) VALUES (?,?,?,?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email']) #Eduardo
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST')) #Eduardo
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':    
            username = request.form.get('username', None) #Eduardo
            password = request.form.get('password', None) #Eduardo
            email = request.form.get('email', None) #Eduardo
            
            db = get_db() #Eduardo
            error = None

            if not username: #Eduardo
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username):
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password: #Eduardo
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('SELECT id FROM USER WHERE USERNAME=?', (username,)).fetchone() is not None: #Eduardo
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html') #Eduardo
            
            if (not email or (not utils.isEmailValid(email))): #Eduardo
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html') #Eduardo
            
            if (not utils.isPasswordValid(password)):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                'INSERT INTO activationlink (challenge, state, username, password, salt, email) VALUES (?,?,?,?,?,?)', #Eduardo
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()
            
            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') #Eduardo
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST')) #Eduardo
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': #Eduardo
            password = request.form.get('password', None) #Eduardo
            password1 = request.form.get('password1', None) #Eduardo
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                print("authid")
                return render_template('auth/forgot.html')                

            if not password: #Eduardo
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid) #Eduardo

            if password1 != password: #Eduardo
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid) #Eduardo

            if not utils.isPasswordValid(password):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db() #Eduardo
            attempt = db.execute(
                'SELECT * FROM forgotlink WHERE ID = ? AND STATUS = ?', (authid, utils.F_ACTIVE) #Eduardo
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    'UPDATE forgotlink SET STATUS = ? WHERE ID = ?', (utils.F_INACTIVE, attempt['id'])#Eduardo
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    'UPDATE USER SET PASSWORD = ?, SALT = ? WHERE ID = ?', (hashP, salt, attempt['userid']) #Eduardo
                )
                db.commit()
                return redirect(url_for('auth.login')) #Eduardo
            else:
                flash('Invalid')
                return render_template('auth/forgot.html') #Eduardo

        return render_template('auth/change.html') #Eduardo
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': #Eduardo
            number = request.args['auth'] 
            
            db = get_db() #Eduardo
            attempt = db.execute(
                'SELECT * FROM forgotlink WHERE CHALLENGE = ? AND STATUS = ?', (number, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/change.html')


@bp.route('/forgot', methods=('GET', 'POST')) #Eduardo
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form.get('email', None) #Eduardo
            
            if (not email or (not utils.isEmailValid(email))): #Eduardo
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'SELECT * FROM user WHERE email = ?', (email,) #Eduardo
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    'UPDATE forgotlink SET STATE = ? WHERE USERID = ?', (utils.F_INACTIVE, user['id']) #Eduardo
                )
                db.execute(
                    'INSERT INTO forgotlink (USERID, CHALLENGE, STATE) VALUES (?,?,?)', #Eduardo
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html') #Eduardo
    finally: #Eduardo
        close_db() #Eduardo


@bp.route('/login', methods=('GET', 'POST')) #Eduardo
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': #Eduardo
            username = request.form.get('username', None) #Eduardo
            password = request.form.get('password', None) #Eduardo

            if not username: #Eduardo
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password: #Eduardo
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html') #Eduardo

            db = get_db() #Eduardo
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if not user['username']: #Eduardo
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user['username'] #Eduardo
                return redirect(url_for('inbox.show'))

            flash(error)

        #return render_template('inbox/show.html') #Eduardo
        return render_template('auth/login.html') #Eduardo
    except:
        return render_template('auth/login.html') #Eduardo
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id') #Eduardo

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT id FROM USER WHERE USERNAME=?', (user_id,) #Eduardo
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.clear() #Eduardo
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view