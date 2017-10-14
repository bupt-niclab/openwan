import os
import sys

reload(sys)  # Reload is a hack
sys.setdefaultencoding('UTF8')

# API_URL = "http://172.27.102.38:8000/"
API_URL = "http://112.35.29.129:8000/"
SECRET_KEY = os.urandom(24)
LOG_FILE = "controller.log"
HOST = "127.0.0.1"
EAUTH = "pam"



SQLALCHEMY_DATABASE_URI = 'sqlite:///template.sqlite'
SQLALCHEMY_TRACK_MODIFICATIONS = 'True'


