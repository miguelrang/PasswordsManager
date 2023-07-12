from flask import (
    Flask,
    render_template,
    jsonify,
    redirect,
    request,
    url_for,
    make_response,
    flash,
    abort
)
from flask_restful import Resource, Api # API
from user_agents import parse # idetnify type device
from bleach import clean as sanitize # sanitize
from argon2 import PasswordHasher # cryptography
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
from CSRFWidgets import * # CSRF Token
from validator import * # valitate
import base64
import sqlite3 # db
import jwt # for token
import os
import requests


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(16)
app.secret_key:bytes = os.urandom(16) # \xe2\...
csrf_token = CSRFProtect(app)
api = Api(app, decorators=[csrf_token.exempt])
token_key:str = os.environ.get("TOKEN_KEY") # token
pepper:bytes = os.environ.get("PEPPER").encode() # pepper
secret_key:bytes = os.environ.get('SECRET_KEY').encode()
secret_key:bytes = base64.urlsafe_b64encode(secret_key.ljust(32, b'\0')) # passwords
cipher_suite = Fernet(secret_key) # user passwords
ph = PasswordHasher(
	hash_len=32,
	salt_len=16,
	time_cost=2,
	memory_cost=102400
)


def getSalt() -> bytes:
    """ Random characters to 'complete' the password.
    """
    return os.urandom(16)


def getHash(password:str, salt:bytes) -> bytes:
    """ We 'encrypt' the password joining salt, password and pepper...
    """
    return ph.hash(salt + password.encode() + pepper)


def getToken():
    return request.cookies.get('token')


def getPasswords(id:int, token:str) -> dict:
	url = "http://localhost:5000/passwords"
	response = requests.post(url, json={"id":str(id), "token":token})
	if response.status_code == 200:
		return response.json()
	else:
		return {"error": "Lo sentimos, ha surgido un error."}

#class CSRFLogin(Resource):
#    def get(self):
#        form = LoginForm()
#        response = jsonify({"csrf_token": form.csrf_token.current_token})
#        response.headers.add('X-CSRFToken', form.csrf_token.current_token)
#        return response


#class CSRFClipboard(Resource):
#    def get(self):
#       form =  PasswordsForm()
#       return jsonify({"csrf_token": form.csrf_token.current_token})
class Passwords(Resource):
    def post(self):
        data = request.get_json()
        id:str = data["id"]
        token:str = data["token"]
        token_response = valid_token(token, token_key)
        if token_response == True: #nalgon
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            if str(decoded_token["id"]) == id:
                with sqlite3.connect("PasswordManager.db") as db:
                    data = db.execute(
        	            """
        	                SELECT key, value FROM Password
        	                WHERE ID_account=?;
        	            """,(id,)
        	        ).fetchall()
                passwords = dict()
                for password in data:
                    passwords[password[0]] = password[1].decode()
                # example: passwords = {"facebook": "face-c0ntr453ñ4", "twitter": "twitt3r-c0ntr4señ4"}
                return jsonify(passwords)
            else:
                return jsonify({"error": "Lo sentimos, a ocurrido un error."})
        else:
            return jsonify({"error": decoded_token[0]})


class Login(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##
        try:
            user:str = sanitize(request.form.get("user"))
            password:str = sanitize(request.form.get('password'))
        except:
            data = request.get_json()
            user = data.get('user')
            password = data.get('password')
        login = LoginForm()
        signup = SignUpForm()
        data = {
            "user": user,
            "password": password,
            "form":{"login":login,"signup":signup},
            "username": "",
            "pass1": "",
            "pass2": ""
        }
        error = None
        # we validate inputs...
        #if login.validate_on_submit():
        if not is_username(user):
            error = (
                "Nombre de usuario invalido. "
                "Por favor, verifique los datos hayan sido agregados correctamente",
                "error"
            )

        if not valid_password(password):
            error = (
                "Contraseña invalida. ",
                "error"
            )

        ##
        # we get data user to compare...
        with sqlite3.connect('PasswordManager.db') as db:
            dat = db.execute(
                """
                    SELECT a.ID_account, a.username, a.password, s.salt FROM Salt s
                        INNER JOIN(
                            SELECT ID_account, username, password
                            FROM Account
                        ) a
                        ON a.ID_account=s.ID_account
                    WHERE username = ?;
                """, (user, )
            ).fetchone()
        # if user exist...
        if dat:
            try:
                # we valid password
                #            pass:db, salt + pass:typed + pepper:enivronment
                if ph.verify(dat[2], dat[3] + password.encode() + pepper):
                    # creating cookies
                    token = jwt.encode(
                        {
                            "id": dat[0],
                            "username": dat[1]
                        },
                        token_key, algorithm="HS256"
                    )

                    if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                        return jsonify({"token":token})
                    else: # PC / Navigator
                        response = make_response(redirect(url_for("index")))
                        response.set_cookie("token", token, max_age=3600, secure=True, httponly=True)
                        return response
                else:
                    error = "Usuario o contraseña incorrectos.", "error"
            except Exception as e:
                error = "Lo sentimos, no se ha podido iniciar sesión (Usuario y/o contraseña incorrectos).", "error"
        else:
            error = "Lo sentimos, no se ha podido iniciar sesión (Usuario y/o contraseña incorrectos).", "error"
        #else:
        #    if len(user) > 0 and len(user) < 3:
        #        error = "El nombre de usuario debe de contener al menos 3 caracteres.", "warning"
        #    elif len(password) > 0 and len(password) < 8:
        #        error = "La contraseña debe de contener al menos 8 caracteres.", "warning"
        #    elif user == "" and password == "":
        #        error = "Campos de usuario y contraseña vacíos. Debe de llenar ambos campos.", "info"
        #    elif user == "":
        #        error = "Campo de usuario vacío. Debe de llenarlo para continuar.", "info"
        #    else:
        #        error = "Campo de contraseña vacío. Debe de llenarlo para continuar", "info"

        data.update({'error':error[0]})
        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            data.pop("form")
            return jsonify(data)
        else: # PC / Navigator
            flash(error[0], error[1])
            return make_response(render_template('index.html', data=data))


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)


class SignUp(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##
        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            data:dict = request.get_json()
            username:str = sanitize(data["user"])
            pass1:str = sanitize(data["pass1"])
            pass2:str = sanitize(data["pass2"])

        else:
            username:str = sanitize(request.form.get("username"))
            pass1:str = sanitize(request.form.get("pass1"))
            pass2:str = sanitize(request.form.get("pass2"))
            login = LoginForm()
            signup = SignUpForm()
            data = {
                "user": "",
                "password": "",
                "form":{"login":login,"signup":signup},
                "username": username,
                "pass1": pass1,
                "pass2": pass2
            }
        error = None
        #if signup.validate_on_submit():
        if not is_username(username):
            error = (
                "Nombre de usuario invalido. "
                "Por favor, verifique que el usuario haya sido agregados correctamente",
                "error"
            )

        if not valid_password(pass1):
            error = (
                "Contraseña invalida. "
                "Por favor, verifique que la contraseña haya sido agregados correctamente",
                "error"
            )

        elif pass1 != pass2:
            error = (
                "¡Las contraseñas no coinciden! "
                "Por favor, verifica que sean iguales.",
                "error"
            )

        ## if everything is ok...
        try:
            salt = getSalt()
            password_hashed = getHash(pass1, salt)
            # saving user...
            with sqlite3.connect('PasswordManager.db') as db:
                # save user and password
                db.execute(
                    """
                        INSERT INTO Account(username, password)
                        VALUES(?, ?);
                    """, (username, password_hashed)
                )
                id_account:int = db.execute(
                    """
                        SELECT ID_account FROM Account
                        WHERE username = ? and password = ?;
                    """, (username, password_hashed)
                ).fetchone()[0]

                id_account:str = str(id_account)
                # save salt
                db.execute(
                    """
                        INSERT INTO Salt(ID_account, salt)
                        VALUES(?, ?);
                    """, (id_account, salt)
                )
            # creating cookies
            token = jwt.encode(
                {
                    "id": str(id_account),
                    "username": username
                },
                token_key, algorithm="HS256"
            )
            if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                return jsonify({"success": True, "token": token})
            else:
                response = make_response(redirect(url_for("index")))
                response.set_cookie("token", token, max_age=3600, secure=True, httponly=True)
                flash("¡Excelente, {}! Tu cuenta a sido creada con éxito.".format(username), "success")
                return response
        except Exception as e:
            error = ("Lo sentimos, el nombre de usuario ya existe. {}".format(e), "info")

        #else:
        #    if len(username) > 0 and len(username) < 3:
        #        error = ("El nombre de usuario debe de contener al menos 3 caracteres.", "warning")
        #    elif (len(pass1) > 0 and len(pass1) < 8) or (len(pass2) > 0 and len(pass2) < 8):
        #        error = ("La contraseña debe de contener al menos 8 caracteres.", "warning")
        #    elif username == "" and password == "":
        #        error = ("Campos de usuario y contraseña vacíos. Debe de llenar todos los campos.", "warning")
        #    elif username == "":
        #        error = ("Debe de llenar el nombre de usuario para continuar.", "warning")
        #    else: # password
        #        error = ("Campo de contraseña vacío. Debe de llenarlo para continuar", "warning")

        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            return jsonify({"error": error[0]})
        else:
            data.update({"error": error})
            flash(error[0], error[1])
            return make_response(render_template('index.html', data=data))


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)


class SavePassword(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##

        #passwords = AddPasswordForm()
        try:
            key:str = sanitize(request.form.get('key'))
            value:str = sanitize(request.form.get('value'))
            token = getToken()
        except:
            data:dict = request.get_json()
            key:str = sanitize(data["key"])
            value:str = sanitize(data["value"])
            token:str = data["token"]
        error = None
        #if passwords.validate_on_submit():
        token_response = valid_token(token, token_key)
        if token_response == True:
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            all_passwords = getPasswords(decoded_token['id'], token)
            to_continue=True
            for passw in all_passwords:
                if passw == key:
                    to_continue = False
                    error = (
                        "Esta clave ya esta registrada. Por favor, intente con otra",
                        "warning"
                    )
                    break

            if to_continue:
                with sqlite3.connect('PasswordManager.db') as db:
                    pencrypted:bytes = cipher_suite.encrypt(value.encode())
                    db.execute(
                        """
                            INSERT INTO Password(ID_account, key, value)
                            VALUES(?, ?, ?);
                        """, (str(decoded_token["id"]), key, pencrypted)
                    )
                    db.commit()
            else:
                error = (
                    "Esta clave ya esta registrada. Por favor, intente con otra",
                    "warning"
                )

        else:
            error = (token_response[0], token_response[1])
        #else:
        #    if key == '' or value == '':
        #        error = ("El campo 'key' y 'value' deben de tener al menos un caracter.", "error")

        #    else:
        #        error = ("Ah ocurrido un error inesperado. Verifique que los campos se hayan llenado correctamente.", "error")

        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            if error == None:
                return jsonify({"success": to_continue, "value": pencrypted.decode()})
            else:
                return jsonify({"error": error[0]})
        else:
            if error != None:
                flash(error[0], error[1])

            return redirect(url_for('index'))


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)


class Clipboard(Resource):
    def post(self):
        encrypted:bytes = request.get_json().get('content').encode()
        decrypted:str = cipher_suite.decrypt(encrypted).decode()
        return jsonify({"value": decrypted})


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)


class RemovePassword(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##

        try:
            pass_form = PasswordsForm()
            key:str = request.form['delete']
            token:str = getToken()
        except:
            data = request.get_json()
            key:str = data["key"]
            token:str = data["token"]
        #if pass_form.validate_on_submit():
        token_response = valid_token(token, token_key)
        if token_response == True:
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            with sqlite3.connect('PasswordManager.db') as db:
                db.execute(
                    """
                        DELETE FROM Password
                        WHERE ID_account=? AND key=?;
                    """, (str(decoded_token['id']), key)
                )
                db.commit()

        else:
            if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                return False
            else:
                flash(token_response[0], token_response[1])

        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            return True
        else:
            return redirect(url_for('index'))


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)


class AlterAccount(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##

        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            data = request.get_json()
            pressed:str = data["pressed"]
            token:str = data["token"]
        else:
            information = InformationForm()
            token:str = getToken()
            pressed:str = request.form

        token_response = valid_token(token, token_key)
        error = None
        if token_response == True:
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            # USERNAME
            if "upd_username" in pressed:
                if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                    username:str = sanitize(data["username"])
                else:
                    username:str = sanitize(request.form.get("username"))

                ###if information.validate_on_submit():
                if len(username) > 2:
                    if is_username(username):
                        with sqlite3.connect('PasswordManager.db') as db:
                            exist = db.execute(
                                '''
                                SELECT username FROM Account
                                WHERE username = ? AND ID_account != ?;
                                ''', (username, str(decoded_token["id"]))
                            ).fetchone()

                        if not exist:
                            with sqlite3.connect('PasswordManager.db') as db:
                                db.execute(
                                    '''
                                    UPDATE Account
                                            SET username=?
                                        WHERE ID_account=?;
                                    ''',(username, str(decoded_token["id"]))
                                )
                                db.commit()

                            new_token = jwt.encode(
                                {"id": decoded_token["id"], "username": username},
                                token_key, algorithm="HS256"
                            )
                            if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                                return jsonify({"success": True, "token": new_token})
                            else:
                                flash(
                                    "El nombre de usuario a sido actualizado con éxito.",
                                    "success"
                                )
                                response = make_response(redirect(url_for('account')))
                                response.set_cookie("token", new_token, max_age=3600, secure=True, httponly=True)
                                return response
                        else:
                            error = (
                                "Lo sentimos, este nombre de usuario ya existe.",
                                "error"
                            )

                    else:
                        error = (
                            "No parece ser un nombre de usuario valido",
                            "error"
                        )
                else:
                    error = (
                        "El nombre de usario debe de tener al menos 3 caracteres.",
                        "error"
                    )

            # PASSWORD
            elif "upd_password" in pressed:
                print("CONTRASEÑA 1")
                print("CONTRASEÑA 1")
                print("CONTRASEÑA 1")
                print("CONTRASEÑA 1")
                print("CONTRASEÑA 1")

                if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                    password = sanitize(data["password"])
                    new_password1 = sanitize(data["new_password1"])
                    new_password2 = sanitize(data["new_password2"])
                else:
                    password = sanitize(request.form.get("actual_password"))
                    new_password1 = sanitize(request.form.get("new_password1"))
                    new_password2 = sanitize(request.form.get('new_password2'))

                print("CONTRASEÑA 2")
                print("CONTRASEÑA 2")
                print("CONTRASEÑA 2")
                print("CONTRASEÑA 2")

                ###if information.validate_on_submit():
                if valid_password(password):
                    print("CONTRASEÑA 3")
                    print("CONTRASEÑA 3")
                    print("CONTRASEÑA 3")
                    print("CONTRASEÑA 3")

                    with sqlite3.connect('PasswordManager.db') as db:
                        dat:tuple = db.execute(
                            '''
                            SELECT a.password, s.salt FROM Salt s
                                INNER JOIN(
                                    SELECT ID_account, password
                                    FROM Account
                                ) a
                                ON a.ID_account=s.ID_account
                            WHERE s.ID_account = ?;
                            ''', (str(decoded_token['id']),)
                        ).fetchone()

                    passw = dat[0]
                    if type(passw) == str():
                        passw = passw.encode()
                    salt = dat[1]
                    try:
                        print(passw, type(passw))
                        if ph.verify(passw, salt + password.encode() + pepper):
                            print("CONTRASEÑA 4")
                            print("CONTRASEÑA 4")
                            print("CONTRASEÑA 4")
                            print("CONTRASEÑA 4")
                            print("CONTRASEÑA 4")

                            if new_password1 == new_password2:
                                print("CONTRASEÑA 4+1")
                                print("CONTRASEÑA 4+1")
                                print("CONTRASEÑA 4+1")
                                print("CONTRASEÑA 4+1")
                                print("CONTRASEÑA 4+1")

                                if valid_password(new_password1):
                                    print("CONTRASEÑA 4+2")
                                    print("CONTRASEÑA 4+2")
                                    print("CONTRASEÑA 4+2")
                                    print("CONTRASEÑA 4+2")
                                    print("CONTRASEÑA 4+2")

                                    if len(new_password1) > 7:
                                        print("CONTRASEÑA 7")
                                        print("CONTRASEÑA 7")
                                        print("CONTRASEÑA 7")
                                        print("CONTRASEÑA 7")
                                        print("CONTRASEÑA 7")

                                        with sqlite3.connect('PasswordManager.db') as db:
                                            new_salt = getSalt()
                                            new_password = getHash(new_password1, new_salt)
                                            db.execute(
                                                '''
                                                    UPDATE Account
                                                        SET password=?
                                                    WHERE ID_account=?;
                                                ''',(new_password, str(decoded_token["id"]))
                                            )

                                            db.execute(
                                                '''
                                                    UPDATE Salt
                                                        SET salt=?
                                                    WHERE ID_account=?;
                                                ''', (new_salt, decoded_token['id'])
                                            )
                                            db.commit()

                                        print("CONTRASEÑA 8")
                                        print("CONTRASEÑA 8")
                                        print("CONTRASEÑA 8")
                                        print("CONTRASEÑA 8")
                                        print("CONTRASEÑA 8")

                                        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                                            return jsonify({"success": True})
                                        else:
                                            flash(
                                                "La contraseña ha sido actualizada correctamente.",
                                                "success"
                                            )
                                    else:
                                        error = (
                                            "La longitud de la contraseña debe de ser de al menos 8 caracteres.",
                                            "error"
                                        )
                                else:
                                    error = (
                                        "La nueva contraseña no es valida.",
                                        "warning"
                                    )
                            else:
                                error = (
                                    "Las contraseñas no coinciden. Verifique que las haya escrito correctamente.",
                                    "error"
                                )
                        else:
                            error = (
                                "Contraseña Incorrecta.",
                                "error"
                            )
                    except:
                        error = (
                            "Contraseña Incorrecta.",
                            "error"
                        )
                else:
                    error = (
                        "No parece ser una contraseña valida.",
                        "error"
                    )

            # DELETE ACCOUNT
            elif "del_account" in pressed:
                if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                    confirm = sanitize(data["msg"])
                    password = sanitize(data["password"])
                else:
                    confirm = sanitize(request.form.get('confirm'))
                    password = sanitize(request.form.get('password'))

                ###if information.validate_on_submit():
                if confirm == '':
                    error = (
                        "Texto sin añadir",
                        "error"
                    )

                elif confirm != 'Eliminar mi Cuenta':
                    error = (
                        "Texto Incorrecto",
                        "error"
                    )

                else: # correct
                    if valid_password(password):
                        with sqlite3.connect('PasswordManager.db') as db:
                            dat:tuple = db.execute(
                                '''
                                SELECT a.password, s.salt FROM Salt s
                                    INNER JOIN(
                                        SELECT ID_account, password
                                        FROM Account
                                    ) a
                                    ON a.ID_account=s.ID_account
                                WHERE s.ID_account = ?;
                                ''', (str(decoded_token['id']),)
                            ).fetchone()

                        passw = dat[0]
                        if type(passw) == str():
                            passw = passw.encode()
                        salt = dat[1]
                        try:
                            if ph.verify(passw, salt + password.encode() + pepper):
                                with sqlite3.connect("PasswordManager.db") as db:
                                    db.execute('DELETE FROM Account WHERE ID_account=?', (str(decoded_token["id"]),))
                                    db.execute('DELETE FROM Salt WHERE ID_account=?', (str(decoded_token["id"]),))
                                    db.execute('DELETE FROM Password WHERE ID_account=?', (str(decoded_token["id"]),))
                                    db.commit()

                                if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                                    return {"success": True}
                                else:
                                    flash("La cuenta se ha eliminado con éxito.", "error")
                                    response = make_response(redirect(url_for('index')))
                                    response.delete_cookie('token')
                                    return response
                            else:
                                error = (
                                    "Contraseña Incorrecta",
                                    "error"
                                )

                        except:
                            error = (
                                "Contraseña Incorrecta",
                                "error"
                            )
                    else:
                        error = (
                            "Contraseña invalida.",
                            "error"
                        )

            # ERROR
            if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                return jsonify({"error": error[0]})

            else:
                if error:
                    flash(error[0], error[1])

                return redirect(url_for('account'))

        else:
            error = (token_response[0], token_response[1])

            if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
                return jsonify({"error": error[0]})

            else:
                flash(error[0], error[1])
                return redirect(url_for('index'))

    def get(self):
        return redirect(url_for('account'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)


class CloseSession(Resource):
    def post(self):
        ## device
        user_agent_string = request.headers.get('User-Agent')
        user_agent = parse(user_agent_string)
        ##
        if user_agent.is_mobile or user_agent.is_tablet or "Python" in user_agent.get_browser():
            return {'close_session': None}
        else:
            response = make_response(redirect(url_for('index')))
            response.delete_cookie('token')
            return response


    def get(self):
        return redirect(url_for('index'))

    def put(self):
        abort(403)

    def delete(self):
        abort(403)

    def patch(self):
        abort(403)

    def options(self):
        abort(403)
