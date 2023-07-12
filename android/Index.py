from kivymd.app import MDApp
from kivymd.uix.floatlayout import MDFloatLayout

from kivy.uix.screenmanager import Screen
#from kivy.properties import (
#    StringProperty,
#    BooleanProperty,
#    ObjectProperty
#)
#from kivy.clock import mainthread

import threading
import requests
import json


class Index(Screen):
    def __init__(self, **kwargs):
        super(Index, self).__init__(**kwargs)
        global app
        app = MDApp.get_running_app()


    def login_validate(self, data: dict):
        """
        url_csrf = "http://localhost:5000/CSRFLogin"
        response_csrf = requests.get(url_csrf)
        csrf_token = response_csrf.json()['csrf_token']

        headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf_token
        }
        """
        url = "http://localhost:5000/login-validate"
        response = requests.post(url, json=data)#, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if "token" in data.keys():
                app.setToken(token=data["token"])
                sc:object = app.root.get_screen("signup")
                app.to_empty(
                    [
                        sc.ids.username.ids.input,
                        sc.ids.passw1.ids.input,
                        sc.ids.passw2.ids.input,
                        self.ids.username,
                        self.ids.passw
                    ]
                )
                app.root.get_screen("pm").setData(data["token"], tab=True)
            else:
                app.openDialog(
                    title="Error",
                    text=data["error"]
                )
        else:
            app.openDialog(
                title="Algo salio mal",
                text="Lo sentimos, ocurrió un error inesperado. Por favor, intentelo más tarde."
            )

        app.loading(self.ids.loading)
