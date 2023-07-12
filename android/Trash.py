import requests

"""
with requests.Session() as r:
    url = "http://localhost:5000/CSRFLogin"
    response = r.get(url)
    csrf_token = response.headers.get('X-CSRFToken')
    data = {"user": "mike", "password":"contraseña"}
    headers = {"Content-Type": "application/json"}
    url = "http://localhost:5000/login-validate"
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        print(response.json())
    else:
        print("Error: {} - {}".format(response.status_code, response.content))
"""
# POST
data = {
    "user": "mike",
    "password": "contraseña"
}
#headers = {
#    "Content-Type": "application/json",
#    "X-CSRFToken": csrf_token
#}
url = "http://localhost:5000/login-validate"
response = requests.post(url, json=data)#, headers=headers)

# Procesar la respuesta
if response.status_code == 200:
    id = str(19)
    token = response.json()["token"]
    url = "http://localhost:5000/passwords"
    response = requests.post(url, json={"id":id, "token":token})
    if response.status_code == 200:
        print(response.json())
    else:
        print("Error: {} - {}".format(response.status_code, response.content))
else:
    print("Error: {} - {}".format(response.status_code, response.content))
    # Manejar el error de acuerdo a tus necesidades
