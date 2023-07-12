from flask import request
from user_agents import parse # idetnify type device
import email_validator
import jwt
import re


def is_username(username:str)-> bool:
    """This function validate if the param (username) is an
    username.

    Args:
        username (str): String sent by the user
    Returns:
        bool: Is it an username or not
    """
    validate = re.compile(r'[a-z]([a-z]|[0-9]|_)*')
    if validate.fullmatch(username):
        return True
    else:
        return False


def is_email(email:str)-> bool:
    """Validate if this is an email using the
    email_validate module.

    Args:
        email (str): 'email' typed by the user.

    Returns:
        bool: is an email or not?
    """
    try:
        email_validator.validate_email(email)
        return True
    except:
        return False


def valid_password(password:str) -> bool:
    """ Validate if the 'password' has the characteristics
        we need.
    Args:
        password (str): 'password' typed by the user
    """
    validate = re.compile(r'([a-z]|[A-Z]|-|_|[0-9]|ñ)+')
    if validate.fullmatch(password):
        return True
    else:
        return False


def valid_token(token:str, token_key:str)-> bool or tuple:
    """ Validate token
    Returns:
        bool: True if it's a valid token.
            or
        tuple: 0: Message to show - 1: Type error
    """
    if token:
        try:
            decoded_token = jwt.decode(token, token_key, algorithms=['HS256'])
            return True
        except jwt.ExpiredSignatureError:
            return (
                "¡La sesión a expirado! Por favor, inicie sesión de nuevo.",
                "info"
            )
        except jwt.InvalidTokenError:
            return (
                "¡Token Invalido! Por favor, inicie sesión de nuevo.",
                "error"
            )
    else:
        return None, None
