from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    validators
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


class CloseSessionForm(FlaskForm):
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
