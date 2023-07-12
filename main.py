from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    make_response, # for token
    flash,
    jsonify,
    abort
)
from flask_restful import Api
from argon2 import PasswordHasher
#from cryptography.fernet import Fernet
from validator import * # my validators
from bleach import clean as sanitize # sanitize
import sqlite3
#import base64
import jwt # for token
import os

from CSRFWidgets import *
from api import *


#app = Flask(__name__)
#app.config["SECRET_KEY"] = os.urandom(16)
#app.secret_key:bytes = os.urandom(16) # \xe2\...
#api = Api(app)
#token_key:str = os.environ.get("TOKEN_KEY") # token ######################################3
#pepper:bytes = os.environ.get("PEPPER").encode() # pepper
#secret_key:bytes = os.environ.get('SECRET_KEY').encode()
#secret_key:bytes = base64.urlsafe_b64encode(secret_key.ljust(32, b'\0')) # passwords
#cipher_suite = Fernet(secret_key) # user passwords
#csrf_token = CSRFProtect(app)
#ph = PasswordHasher(
#	hash_len=32,
#	salt_len=16,
#	time_cost=2,
#	memory_cost=102400
#) ####################################################################


def getToken():
    return request.cookies.get('token')


@app.route('/', methods=["GET", "POST"])
def index() -> render_template:
    """ Main route where we enter to 'login/signup' or account.
    """
    token = getToken()
    token_response = valid_token(token, token_key)
    if token_response == True: # logged
        decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
        data = {
            "passwords": getPasswords(decoded_token['id'], token),
            "form": {
                "add_password": AddPasswordForm(),
                "passwords": PasswordsForm(),
                "close_session": CloseSessionForm(),
            }
        }
        return render_template('logged_passwords.html', data=data)

    else: # NOT Logged
        login = LoginForm()
        signup = SignUpForm()

        data = {
            "user": "",
            "password": "",
            "form":{"login":login,"signup":signup},
            "username": "",
            "pass1": "",
            "pass2": ""
        }

        if token_response:
            flash(token_response[0], token_response[1])

        return render_template('index.html', data=data)


@app.route('/account', methods=["GET", "POST"])
def account() -> render_template:
    """ User data
    """
    token = getToken()
    token_response = valid_token(token, token_key)
    if token_response == True: # logged
        decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
        data = {
            "id": decoded_token['id'],
            "username": decoded_token['username'],
            #"email": decoded_token["email"],
            "form": {"information": InformationForm(), 'close_session': CloseSessionForm()}
        }
        return render_template('logged_account.html', data=data)

    else: # NOT Logged
        login = LoginForm()
        signup = SignUpForm()

        data = {
            "user": "",
            "password": "",
            "form":{"login":login,"signup":signup},
            "username": "",
            "pass1": "",
            "pass2": ""
        }

        if token_response:
            flash(token_response[0], token_response[1])

        return render_template('index.html', data=data)


@app.errorhandler(400)
def error400(error):
    return render_template("ErrorPage.html",msg="lo sentimos, a ocurrido un error.".title())


@app.errorhandler(403)
def error403(error):
    return render_template("ErrorPage.html",msg="Metodo invalido.".title())


@app.errorhandler(404)
def error404(error):
    return render_template("ErrorPage.html",msg="esta página no existe.".title())


@app.errorhandler(500)
def error500(error):
    return render_template("ErrorPage.html",msg="lo sentimos, estamos teniendo problemas para cargar la página.".title())


# API Resources
####################################3api.add_resource(CSRFLogin, '/CSRFLogin')
api.add_resource(Login, '/login-validate')
#
#api.add_resource(CSRFSignup, '/CSRFSignup')
api.add_resource(SignUp, '/signup-validate')
#
api.add_resource(Passwords, "/passwords")
#
#api.add_resource(CSRFSavePassword, '/CSRFSavePassword')
api.add_resource(SavePassword, '/add-password')
#
#################api.add_resource(CSRFClipboard, '/CSRFClipboard')
api.add_resource(Clipboard, '/clipboard')
#
#api.add_resource(CSRFDelPassword, '/CSRFDelPassword')
api.add_resource(RemovePassword, '/del-password')
#
#api.add_resource(CSRFAlterAccount, '/CSRFAlterAccount')
api.add_resource(AlterAccount, '/alter-account')
#
#api.add_resource(CSRFCloseSession, '/CSRFCloseSession')
api.add_resource(CloseSession, '/close-session')


if __name__ == "__main__":
    app.run(debug=True)
