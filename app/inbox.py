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
        QUERY
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
        
        if not subject:
            flash('Subject field is required')
            return render_template('inbox/send.html') #modificado OSCAR
        
        if not body:
            flash('Body field is required')
            return render_template('inbox/send.html') #modificado OSCAR
        
        error = None    
        userto = None 
        
        userto = db.execute(
            QUERY, (to_username,)
        ).fetchone()
        
        if userto is None:
            error = 'Recipient does not exist'
     
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                QUERY,
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')