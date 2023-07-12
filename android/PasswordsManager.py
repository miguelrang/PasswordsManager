from kivymd.app import MDApp
from kivymd.uix.floatlayout import MDFloatLayout
from kivymd.uix.tab import MDTabsBase

from kivy.uix.screenmanager import Screen
from kivy.lang import Builder
from kivy.clock import mainthread
from kivy.utils import platform
import clipboard # Android
import pyperclip # Windows / Mac OS / Linux

import threading
import sqlite3
import requests
import jwt


#Builder.load_file('templates/Information.kv')
class Information(MDFloatLayout, MDTabsBase):
	''''''
#Builder.load_file('templates/Passwords.kv')
class Passwords(MDFloatLayout, MDTabsBase):
	''''''

class PasswordsManager(Screen):
	def __init__(self, **kwargs):
		super(PasswordsManager, self).__init__(**kwargs)
		global app
		app = MDApp.get_running_app()


	def getPasswords(self, id:int, token:str) -> dict:
		url = "http://localhost:5000/passwords"
		response = requests.post(url, json={"id":str(id), "token":token})
		if response.status_code == 200:
			return response.json()
		else:
			return {"error": "Lo sentimos, ha surgido un error."}

	@mainthread
	def setData(self, token:str, tab=None):
		decoded_token = jwt.decode(token, app.getTokenKey(), algorithms=['HS256'])
		id:int = decoded_token["id"]
		username:str = decoded_token["username"]

		self.ids.username.ids.input.text = username
		# Passwords
		password = self.getPasswords(id, token)
		if "error" not in password.keys():
			if tab:
				self.ids.tabs.switch_tab(search_by="icon", name_tab="key")
			if password:
				#print(password)
				self.ids.no_passwords.text = ""
				recycle = self.ids.recycle
				recycle.data = []
				for key in password.keys():
					#print("{}: {}".format(key, password[key]))
					recycle.data.append(
						{
							"viewclass": "Password",
							"key": key,
							"value": password[key]#.decode()
						}
					)

			else:
				self.ids.no_passwords.text = "[size=18][color=#0000ff][b]¡No hay contraseñas para mostrar![/b][/color][/size]"
			app.root.current="pm"
		else:
			app.openDialog(
				title="Error",
				text=password["error"]
			)

		self.ids.loading.active = False


	def validEmpty(self):
		if self.ids.recycle.data == []:
			self.ids.no_passwords.text = "[size=18][color=#0000ff][b]¡No hay contraseñas para mostrar![/b][/color][/size]"
		else:
			self.ids.no_passwords.text = ""


	#@mainthread
	def savePassword(self, data:dict):
		key = data["key"]
		value = data["value"]
		if key and value: # not empties
			url = "http://localhost:5000/add-password"
			data = {"key": key, "value": value, "token": app.getToken()}
			response = requests.post(url, json=data)#, headers=headers)
			if response.status_code == 200:
				data = response.json()
				if "success" in data.keys():
					if data["success"] == True:
						self.ids.recycle.data.append(
							{
								"viewclass": "Password",
								"key": key,
								"value": data["value"]
							}
						)
						app.to_empty([self.ids.key.ids.input, self.ids.value.ids.input])
						app.openDialog(
							title="Excelente",
							text="Su contraseña ha sido guardada satisfactoriamente"
						)
					else:
						app.openDialog(
							title="Error",
							text="Lo sentimos, la clave ´{}´ ya existe.".format(key)
						)
				else:
					app.openDialog(
						title="Error",
						text=data["error"]
					)
			else:
				app.openDialog(
					title="Algo salio mal",
					text="Lo sentimos, ocurrió un error inesperado."
				)
		else:
			app.openDialog(
				title="Error",
				text="Debe llenar ambos campos para guardar su contraseña."
			)

		app.loading(self.ids.loading)
		self.validEmpty()


	def delPassword(self, key:str):
		url = "http://localhost:5000/del-password"
		data = {"key": key, "token": app.getToken()}
		response = requests.post(url, json=data)
		if response.status_code == 200:
			success:bool = response.json()
			if success:
				recycle = self.ids.recycle
				for wdg in recycle.data.copy():
					if wdg["key"] == key:
						recycle.data.remove(wdg)
						break
				app.openDialog(
					title="Contraseña Eliminada",
					text="Su contraseña ha sido eliminada correctamente."
				)
			else:
				app.openDialog(
					title="Error",
					text=data["error"]
				)
		else:
			app.openDialog(
				title="Algo salio mal",
				text="Ah ocurrido un error inesperado."
			)

		app.loading(self.ids.loading)
		self.validEmpty()


	def copyClipboard(self, password:str):
		url = "http://localhost:5000/clipboard"
		data = {"content": password}
		response = requests.post(url, json=data)
		password:str = response.json()["value"]
		try:
			if platform == "android":
				clipboard.copy(password)
			elif platform == "ios":
				pass
			else:
				pyperclip.copy(password)

			app.openDialog(
				title="",
				text="Texto Copiado en el Portapapeles."
			)
		except:
			app.openDialog(
				title="Algo salio mal",
				text="Ah ocurrido un error inesperado."
			)

		app.loading(self.ids.loading)


	def updUsername(self, data:dict):
		pressed:str = data["pressed"]
		token:str = app.getToken()
		username:str = data["username"]
		if username:
			if len(username) > 2:
				url = "http://localhost:5000/alter-account"
				data = {"pressed":pressed, "token":token, "username":username}
				response = requests.post(url, json=data)
				if response.status_code == 200:
					success = response.json()
					if "success" in success.keys():
						app.setToken(success["token"])
						app.openDialog(
							title="Actualización existosa",
							text="Su nombre de usuario a sido actualizado con éxito."
						)
					else:
						app.openDialog(
							title="Error",
							text=str(success["error"])
						)
				else:
					app.openDialog(
						title="Algo salio mal",
						text="Lo sentimos, a ocurrido un error inesperado."
					)
			else:
				app.openDialog(
					title="Nombre de Usuario invalido",
					text="El nombre de usuario debe de tener al menos 3 caracteres."
				)
		else:
			app.openDialog(
				title="Campo Vacío",
				text="El nombre de usuario no puede estar vacío"
			)

		app.loading(self.ids.loading)


	def updPassword(self, data:dict):
		pressed:str = data["pressed"]
		token:str = app.getToken()
		password:str = data["password"]
		new_password1:str = data["new_password1"]
		new_password2:str = data["new_password2"]

		if password and new_password1 and new_password2:
			if new_password1 == new_password2:
				url = "http://localhost:5000/alter-account"
				data.update({"token": token})
				response = requests.post(url, json=data)
				if response.status_code == 200:
					success = response.json()
					if "success" in success.keys():
						app.to_empty(
							[
								self.ids.passw.ids.input,
								self.ids.passw1.ids.input,
								self.ids.passw2.ids.input
							]
						)
						app.openDialog(
							title="Actualización de Contraseña Exitosa",
							text="Su contraseña ha sido actualizada con éxito."
						)
					else:
						app.openDialog(
							title="Error",
							text=str(success["error"])
						)
				else:
					app.openDialog(
						title="Algo salio mal",
						text="Ah ocurrido un error inesperado."
					)
			else:
				app.openDialog(
					title="Error",
					text="Las contraseñas no coinciden."
				)
		else:
			app.openDialog(
				title="Error",
				text="Debe de llenar los 3 campos para actualizar la contraseña."
			)

		app.loading(self.ids.loading)


	def removeAccount(self, data:dict):
		pressed:str = data["pressed"]
		token:str = app.getToken()
		msg:str = data["msg"]
		password:str = data["password"]

		if msg == "Eliminar mi Cuenta":
			if password:
				url = "http://localhost:5000/alter-account"
				data.update({"token":token})
				response = requests.post(url, json=data)
				if response.status_code == 200:
					success = response.json()
					if "success" in success.keys():
						app.openDialog(
							title="Cuenta Eliminada",
							text="La cuenta ha sido eliminada con éxito."
						)
						app.setToken("")
						app.to_empty(
							[
								self.ids.username.ids.input,

								self.ids.passw.ids.input,
								self.ids.passw1.ids.input,
								self.ids.passw2.ids.input,

								self.ids.msg.ids.input,
								self.ids.del_pass.ids.input
							],
							recycle=self.ids.recycle
						)
						app.root.current="login"
					else:
						app.openDialog(
							title="Error",
							text=str(success["error"])
						)
				else:
					app.openDialog(
						title="Algo salio mal",
						text="Surgio un error inesperado."
					)
					print(response.status_code)
					print(response.content)
			else:
				app.openDialog(
					title="Error",
					text="Contraseña incorrecta."
				)
		else:
			app.openDialog(
				title="Error",
				text="El texto no fue escrito correctamente."
			)

		app.loading(self.ids.loading)
