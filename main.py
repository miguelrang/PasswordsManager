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
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    validators
)
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from validator import * # my validators
from bleach import clean as sanitize # sanitize
import sqlite3
import base64
import jwt # for token
import os


app = Flask(__name__)
app.secret_key:bytes = os.urandom(16) # \xe2\...
token_key:str = os.environ.get("TOKEN_KEY") # token
pepper:bytes = os.environ.get("PEPPER").encode() # pepper
secret_key:bytes = os.environ.get('SECRET_KEY').encode()
secret_key:bytes = base64.urlsafe_b64encode(secret_key.ljust(32, b'\0')) # passwords
cipher_suite = Fernet(secret_key) # user passwords
csrf_token = CSRFProtect(app)
ph = PasswordHasher(
	hash_len=32,
	salt_len=16,
	time_cost=2,
	memory_cost=102400
)


class LoginForm(FlaskForm):
    user = StringField("Usuario", validators=[validators.DataRequired()])
    password = StringField('Contraseña', validators=[validators.DataRequired()])
    login = SubmitField("Log in")


class SignUpForm(FlaskForm):
    username = StringField("Nombre de Usuario", validators=[validators.DataRequired(), validators.Length(min=3)])
    pass1 = PasswordField('Contraseña', validators=[validators.DataRequired(), validators.Length(min=8)])
    pass2 = PasswordField('Confirmar Contraseña', validators=[validators.DataRequired(), validators.Length(min=8)])
    signup = SubmitField('Sign up')


class CloseSession(FlaskForm):
    close_session = SubmitField("Log out")


class InformationForm(FlaskForm):
    # username
    username = StringField("Nombre de Usuario", validators=[validators.Length(min=3)])
    upd_username = SubmitField("Actualizar")
    # password
    actual_password = PasswordField("Contraseña Actual", validators=[validators.Length(min=8)])
    new_password1 = PasswordField("Nueva Contraseña", validators=[validators.Length(min=8)])
    new_password2 = PasswordField("Confirmar Nueva Contraseña", validators=[validators.Length(min=8)])
    upd_password = SubmitField("Actualizar")

    # delete account
    confirm = StringField("Escriba 'Eliminar mi cuenta'")
    password = PasswordField("Contraseña", validators=[validators.Length(min=8)])
    del_account = SubmitField("Eliminar")


class AddPasswordForm(FlaskForm):
    key = StringField("Identificador (nombre)", validators=[validators.DataRequired(), validators.Length(min=1)])
    value = StringField('Contraseña', validators=[validators.DataRequired(), validators.Length(min=1)])
    save = SubmitField('Guardar')


class PasswordsForm(FlaskForm):
    key = StringField("Identificador (nombre)", validators=[validators.DataRequired(), validators.Length(min=1)])
    value = StringField('Contraseña', validators=[validators.DataRequired(), validators.Length(min=1)])
    delete = SubmitField('Eliminar')


@app.route('/login-validate', methods=["POST", "GET"])
def login_validate() -> redirect or render_template:
    """ Validate inputs for login
    """
    if request.method == "POST":
        user:str = sanitize(request.form.get("user"))
        password:str = sanitize(request.form.get('password'))
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
        # we validate inputs...
        if login.validate_on_submit():
            if not is_username(user):
                flash(
                    "Nombre de usuario invalido. "
                    "Por favor, verifique los datos hayan sido agregados correctamente",
                    "error"
                )

                return render_template('index.html', data=data)
            if not valid_password(password):
                flash(
                    "Contraseña invalida. ",
                    "error"
                )

                return render_template('index.html', data=data)
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

                        response = make_response(redirect(url_for("index")))
                        response.set_cookie("token", token, max_age=3600, secure=True, httponly=True)
                        return response
                    else:
                        flash("Usuario o contraseña incorrectos.", "error")
                        return render_template('index.html', data=data)
                except Exception as e:
                    flash("Lo sentimos, no se ha podido iniciar sesión (Usuario y/o contraseña incorrectos).", "error")
                    return render_template('index.html', data=data)
            else:
                flash("Lo sentimos, no se ha podido iniciar sesión (Usuario y/o contraseña incorrectos).", "error")
                return render_template('index.html', data=data)
        else:
            if len(user) > 0 and len(user) < 3:
                flash("El nombre de usuario debe de contener al menos 3 caracteres.", "warning")
            elif len(password) > 0 and len(password) < 8:
                flash("La contraseña debe de contener al menos 8 caracteres.", "warning")
            elif user == "" and password == "":
                flash("Campos de usuario y contraseña vacíos. Debe de llenar ambos campos.", "info")
            elif user == "":
                flash("Campo de usuario vacío. Debe de llenarlo para continuar.", "info")
            else:
                flash("Campo de contraseña vacío. Debe de llenarlo para continuar", "info")
            return render_template('index.html', data=data)
    else:
        return redirect(url_for('index'))


def getSalt() -> bytes:
    """ Random characters to 'complete' the password.
    """
    return os.urandom(16)


def getHash(password:str, salt:bytes) -> bytes:
    """ We 'encrypt' the password joining salt, password and pepper...
    """
    return ph.hash(salt + password.encode() + pepper)


@app.route('/signup-validate', methods=["GET", "POST"])
def signup_validate() -> redirect or render_template:
    """ Validating data to save user
    """
    if request.method == "POST":
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
        if signup.validate_on_submit():
            if not is_username(username):
                flash(
                    "Nombre de usuario invalido. "
                    "Por favor, verifique que el usuario haya sido agregados correctamente",
                    "error"
                )

                return render_template('index.html', data=data)

            if not valid_password(pass1):
                flash(
                    "Contraseña invalida. "
                    "Por favor, verifique que la contraseña haya sido agregados correctamente",
                    "error"
                )

                return render_template('index.html', data=data)

            elif pass1 != pass2:
                flash(
                    "¡Las contraseñas no coinciden! "
                    "Por favor, verifica que sean iguales.",
                    "error"
                )
                return render_template('index.html', data=data)

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
                response = make_response(redirect(url_for("index")))
                response.set_cookie("token", token, max_age=3600, secure=True, httponly=True)
                flash("¡Excelente, {}! Tu cuenta a sido creada con éxito.".format(username), "success")
                return response
            except Exception as e:
                flash("Lo sentimos, el nombre usuario ya existen.", "info")
                return render_template('index.html', data=data)
        else:
            if len(username) > 0 and len(username) < 3:
                flash("El nombre de usuario debe de contener al menos 3 caracteres.", "warning")
            elif (len(pass1) > 0 and len(pass1) < 8) or (len(pass2) > 0 and len(pass2) < 8):
                flash("La contraseña debe de contener al menos 8 caracteres.", "warning")
            elif username == "" and password == "":
                flash("Campos de usuario y contraseña vacíos. Debe de llenar todos los campos.", "warning")
            elif username == "":
                flash("Debe de llenar el nombre de usuario para continuar.", "warning")
            else: # password
                flash("Campo de contraseña vacío. Debe de llenarlo para continuar", "warning")
            return render_template('index.html', data=data)
    else:
        return redirect(url_for('index'))


def getToken():
    return request.cookies.get('token')


def getPasswords(id:str) -> dict:
    with sqlite3.connect("PasswordManager.db") as db:
        data = db.execute(
            """
                SELECT key, value FROM Password
                WHERE ID_account=?;
            """,(str(id),)
        ).fetchall()
    passwords = dict()
    for password in data:
        passwords[password[0]] = password[1].decode()
    # example: passwords = {"facebook": "face-c0ntr453ñ4", "twitter": "twitt3r-c0ntr4señ4"}
    return passwords


@app.route('/', methods=["GET", "POST"])
def index() -> render_template:
    """ Main route where we enter to 'login/signup' or account.
    """
    token = getToken()
    token_response = valid_token(token)
    if token_response == True: # logged
        decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
        data = {
            "passwords": getPasswords(decoded_token['id']),
            "form": {
                "add_password": AddPasswordForm(),
                "passwords": PasswordsForm(),
                "close_session": CloseSession()
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

        flash(token_response[0], token_response[1])

        return render_template('index.html', data=data)


@app.route('/alter-account', methods=["POST", "GET"])
def alter_account():
    """ Update username or password, or DELETE account
    """
    if request.method == "POST":
        information = InformationForm()
        token = getToken()
        token_response = valid_token(token)
        if token_response == True:
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            # USERNAME
            if "upd_username" in request.form:
                username = sanitize(request.form.get("username"))
                ###if information.validate_on_submit():
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

                        flash(
                            "El nombre de usuario a sido actualizado con éxito.",
                            "success"
                        )
                        new_token = jwt.encode(
                            {"id": decoded_token["id"], "username": username},
                            token_key, algorithm="HS256"
                        )
                        response = make_response(redirect(url_for('account')))
                        response.set_cookie("token", new_token, max_age=3600, secure=True, httponly=True)

                        return response
                    else:
                        flash(
                            "Lo sentimos, este nombre de usuario ya existe.",
                            "error"
                        )

                else:
                    flash(
                        "No parece ser un nombre de usuario valido",
                        "error"
                    )

                ###else:
                ###    flash(
                ###        "El nombre de usuario debe de tener al menos 3 caracteres.",
                ###        "warning"
                ###    )
            # PASSWORD
            elif "upd_password" in request.form:
                password = sanitize(request.form.get("actual_password"))
                new_password1 = sanitize(request.form.get("new_password1"))
                new_password2 = sanitize(request.form.get('new_password2'))
                ###if information.validate_on_submit():
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
                    salt = dat[1]
                    try:
                        if ph.verify(passw, salt + password.encode() + pepper):
                            if valid_password(new_password1):
                                if valid_password(new_password1) == valid_password(new_password2):
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

                                    flash(
                                        "La contraseña ha sido actualizada correctamente.",
                                        "success"
                                    )
                                else:
                                    flash(
                                        "Las contraseñas no coinciden. Verifique que las haya escrito correctamente.",
                                        "error"
                                    )
                            else:
                                flash(
                                    "La nueva contraseña no es valida.",
                                    "warning"
                                )
                        else:
                            flash(
                                "Contraseña Incorrecta.",
                                "error"
                            )
                    except:
                        flash(
                            "Contraseña Incorrecta.",
                            "error"
                        )
                else:
                    flash(
                        "No parece ser una contraseña valida.",
                        "error"
                    )

                ###else:
                ###    if len(password) < 8:
                ###        flash(
                ###            "Contraseña Incorrecta",
                ###            "error"
                ###        )
                ###    elif len(new_password1) < 8 or len(new_password2) < 8:
                ###        flash(
                ###            "La nueva contraseña debe de tener al menos 8 caracteres",
                ###            "warning"
                ###        )
            # DELETE
            elif "del_account" in request.form:
                confirm = sanitize(request.form.get('confirm'))
                password = sanitize(request.form.get('password'))
                ###if information.validate_on_submit():
                if confirm == '':
                    flash(
                        "Texto sin añadir",
                        "error"
                    )

                elif confirm != 'Eliminar mi Cuenta':
                    flash(
                        "Texto Incorrecto",
                        "error"
                    )

                else: # correct
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
                    salt = dat[1]
                    try:
                        if ph.verify(passw, salt + password.encode() + pepper):
                            with sqlite3.connect("PasswordManager.db") as db:
                                db.execute('DELETE FROM Account WHERE ID_account=?', (str(decoded_token["id"]),))
                                db.execute('DELETE FROM Salt WHERE ID_account=?', (str(decoded_token["id"]),))
                                db.execute('DELETE FROM Password WHERE ID_account=?', (str(decoded_token["id"]),))
                                db.commit()

                            response = make_response(redirect(url_for('index')))
                            response.delete_cookie('token')
                            return response
                        else:
                            flash(
                                "Contraseña Incorrecta",
                                "error"
                            )

                    except:
                        flash(
                            "Contraseña Incorrecta",
                            "error"
                        )
                ###else:
                ###    if len(password) < 8:
                ###        flash(
                ###            "Contraseña Incorrecta",
                ###            "error"
                ###        )
            #else:
            #    flash('Ninguno', 'error')

        else:
            flash(token_response[0], token_response[1])

        return redirect(url_for('account'))
    else:
        abort(403)


@app.route('/account', methods=["GET", "POST"])
def account() -> render_template:
    """ User data
    """
    token = getToken()
    token_response = valid_token(token)
    if token_response == True: # logged
        decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
        data = {
            "id": decoded_token['id'],
            "username": decoded_token['username'],
            #"email": decoded_token["email"],
            "form": {"information": InformationForm(), 'close_session': CloseSession()}
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

        flash(token_response[0], token_response[1])

        return render_template('index.html', data=data)


@app.route("/add-password", methods=["POST"])
def add_passwords() -> redirect:
    """ Adding a password more...
    """
    if request.method == "POST":
        passwords = AddPasswordForm()
        key = sanitize(request.form.get('key'))
        value = sanitize(request.form.get('value'))
        if passwords.validate_on_submit():
            token = getToken()
            token_response = valid_token(token)
            if token_response == True:
                decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
                all_passwords = getPasswords(str(decoded_token['id']))
                to_continue=True
                for passw in all_passwords:
                    if passw[1] == key:
                        to_continue = False

                if to_continue:
                    with sqlite3.connect('PasswordManager.db') as db:
                        db.execute(
                            """
                                INSERT INTO Password(ID_account, key, value)
                                VALUES(?, ?, ?);
                            """, (str(decoded_token["id"]), key, cipher_suite.encrypt(value.encode()))
                        )
                        db.commit()
                else:
                    flash(
                        "Esta clave ya esta registrada. Por favor, intente con otra",
                        "warning"
                    )

            else:
                flash(token_response[0], token_response[1])
        else:
            if key == '' or value == '':
                flash("El campo 'key' y 'value' deben de tener al menos un caracter.", "error")

            else:
                flash("Ah ocurrido un error inesperado. Verifique que los campos se hayan llenado correctamente.", "error")

        return redirect(url_for('index'))
    else:
        abort(403)


@app.route('/clipboard', methods=["POST", "GET"])
def clipboard() -> jsonify:
    """ Decrypt the text and copy to clipboard
    """
    if request.method == "POST":
        encrypted:bytes = request.get_json().get('content').encode()
        decrypted:str = cipher_suite.decrypt(encrypted).decode()

        return jsonify({"value": decrypted})
    else:
        abort(403)


@app.route("/del-password", methods=["POST", "GET"])
def del_passwords():
    """ Remove one of the passwords...
    """
    if request.method == "POST":
        pass_form = PasswordsForm()
        key = request.form['delete']
        #if pass_form.validate_on_submit():
        token = getToken()
        token_response = valid_token(token)
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
            flash(token_response[0], token_response[1])

        return redirect(url_for('index'))
    else:
        abort(403)


@app.route("/close-session", methods=["POST", "GET"])
def closeSession():
    if request.method == "POST":
        response = make_response(redirect(url_for('index')))
        response.delete_cookie('token')
        return response
    else:
        abort(403)


@app.errorhandler(400)
def error400(error):
    return render_template("ErrorPage.html",msg="lo sentimos, a ocurrido un error.".title())


@app.errorhandler(403)
def error403(error):
    return render_template("ErrorPage.html",msg="lo sentimos, no puede acceder directamente a esta ruta.".title())


@app.errorhandler(404)
def error404(error):
    return render_template("ErrorPage.html",msg="esta página no existe.".title())


@app.errorhandler(500)
def error500(error):
    return render_template("ErrorPage.html",msg="lo sentimos, estamos teniendo problemas para cargar la página.".title())


if __name__ == "__main__":
    app.run(debug=True) # ssl_context='adhoc',
