from kivy.config import Config
Config.set('graphics', 'resizable', True)

from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDRectangleFlatButton

from kivy.core.window import Window
from kivy.uix.screenmanager import ScreenManager
from kivy.lang import Builder
from kivy.clock import mainthread
from kivy.utils import platform

from Index import *
from SignUp import *
from PasswordsManager import *

#import threading
import os


Builder.load_file("Widgets.kv")
class WindowManager(ScreenManager):
    def __init__(self, **kwargs):
        super(WindowManager, self).__init__(**kwargs)


class main(MDApp):
    def build(self):
        if platform in ["win", "linux", "macosx", "unknown"]:
            Window.size=(530, 690)
            Window.left=530
            Window.top=35

        kv = WindowManager()
        kv.add_widget(Builder.load_file('templates/Index.kv'))
        kv.add_widget(Builder.load_file('templates/SignUp.kv'))
        kv.add_widget(Builder.load_file('templates/PasswordsManager.kv'))

        return kv


    def on_text_validate(self, sc:object, actual:dict, fields:list, data:dict, action:str):
        actual["field"].focus = False
        if actual["field"].text:
            exec = True
            for field in fields.copy():
                if field != actual["field"]:
                    if not field.text:
                        field.focus = True
                        exec = False
                        break
            if exec:
                load = threading.Thread(target=self.loading, args=(sc.ids.loading,))
                if "login" == action:
                    exec = threading.Thread(target=sc.login_validate, args=(data,))
                elif "signup" == action:
                    exec = threading.Thread(target=sc.signup_validate, args=(data,))
                elif "upd_username" == action:
                    exec = threading.Thread(target=sc.updUsername, args=(data,))
                elif "upd_password" == action:
                    exec = threading.Thread(target=sc.updPassword, args=(data,))
                elif "del_account" == action:
                    exec = threading.Thread(target=sc.removeAccount, args=(data,))
                else: # "save_password" == action:
                    exec = threading.Thread(target=sc.savePassword, args=(data,))

                load.start()
                exec.start()
        else:
            actual["field"].focus = True


    def on_focus(self, next:object):
        if self.actual != next:
            self.actual.focus = False
            next.focus = True
            self.actual = next


    @mainthread
    def to_empty(self, fields:list, recycle=list()):
        for field in fields:
            field.text = ""

        if recycle:
            recycle.data = []


    def on_start(self):
        # self.root.current='pm'
        sc = self.root.get_screen("login")
        self.actual = None
        sc.ids.username.ids.input.focus = True


    def setToken(self, token:str):
        self.token = token


    def getToken(self):
        return self.token


    def getTokenKey(self):
        return os.environ.get("TOKEN_KEY")


    @mainthread
    def openDialog(self, title:str, text:str):
        def closeDialog(*args):
            self.dialog.dismiss()

        self.dialog = MDDialog(
            title=title,
            text=text,
            buttons=[
                MDRectangleFlatButton(
                    text="Aceptar",
                    on_press=closeDialog
                )
            ]
        )
        self.dialog.open()


    def loading(self, wdg:object):
        wdg.active = not wdg.active


if __name__ == '__main__':
    main().run()
