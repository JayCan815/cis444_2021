from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token

from tools.logging import logger

def handle_request():
    logger.debug("Login Handle Request")
    #use data here to auth the user
    
    user = {
            "sub" : request.form['username'] #sub is used by pyJwt as the owner of the token
            }
    
    cur = g.db.cursor()
    cur.execute(sql.SQL("SELECT password FROM users WHERE username = %s;"), (user['sub'],))
    pw = cur.fetchone() 
    cur.close()
     
    if pw == None:
        logger.debug('User doesnt exist')
        return json_response(status_=401, message = 'bad credentials', authenticated =  False )
        
        
    if not bcrypt.checkpw( bytes(request.form.get('password'), 'utf-8'), str.encode(pw[0])):
        logger.debug('Invalid password')
        return json_response(status_=401, message = 'Invalid credentials', authenticated =  False )
 

    return json_response( token = create_token(user) , authenticated = True)

