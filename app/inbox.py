from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db() #modificado OSCAR
    messages = db.execute(
        "SELECT M.BODY, M.SUBJECT, M.CREATED, U.USERNAME FROM MESSAGES M INNER JOIN USER U ON U.ID = M.FROM_ID ORDER BY M.CREATED DESC"
        #"SELECT * FROM messages WHERE id='" + str(g.user['id']) + "'" #modificado OSCAR
        #Sugerencia Eduardo  'SELECT M.BODY, M.SUBJECT, M.CREATED, U.USERNAME FROM MESSAGES M INNER JOIN USER U ON U.ID = M.FROM_ID ORDER BY M.CREATED DESC'
    ).fetchall()

    return render_template('inbox/show.html', messages=messages) #modificado OSCAR


@bp.route('/send', methods=('GET', 'POST')) #modificado OSCAR
@login_required
def send():
    if request.method == 'POST': #modificado OSCAR
        from_id = g.user['id'] 
        to_username = g.user['to'] #modificado OSCAR
        subject = g.user['subject'] #modificado OSCAR
        body = g.user['body'] #modificado OSCAR

        db = get_db() #modificado OSCAR
       
        if not to_username:
            flash('To field is required')
            return render_template('inbox/send.html') #modificado OSCAR
        
        if not subject: #modificado OSCAR
            flash('Subject field is required')
            return render_template('inbox/send.html') #modificado OSCAR
        
        if not body: #modificado OSCAR
            flash('Body field is required')
            return render_template('inbox/send.html') #modificado OSCAR
        
        error = None    
        userto = None 
        
        userto = db.execute(
            'SELECT * FROM user email =' + to_username + ';' #modificado OSCAR
            #Sugerencia Eduardo 'SELECT ID FROM USER WHERE USERNAME = ?', (to_username,)
        ).fetchone()
        
        if userto is None:
            error = 'Recipient does not exist'
     
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO message (from_id,to_id,subject,body) VALUES (' + g.user['id'] + ',' + userto['id'] + ',' + subject + ',' + body + ');' #modificado OSCAR
                # sugerencia Eduardo 'INSERT INTO MESSAGES (FROM_ID, TO_ID, SUBJECT, BODY) VALUES (?,?,?,?)',
                # (from_id, userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')