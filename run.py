import sys
from orchestrator.app import app, timer_mission
from flask_sqlalchemy import SQLAlchemy
host = app.config['HOST']
db_url= app.config['SQLALCHEMY_DATABASE_URI']

db = SQLAlchemy(app)

if host == '0.0.0.0' and not '--insecure-debug-run' in sys.argv:
    print ("You try to run controller in debug mode, please confirm by adding --insecure-debug-run option")
    sys.exit(1)

if host == '0.0.0.0':
    print ("""Please be adviced that controller is running in debug mode and """
           """listening to 0.0.0.0 which is very dangerous. If you're not """
           """100% hundred sure of what to do, exit now.""")
# timer_mission()
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')



