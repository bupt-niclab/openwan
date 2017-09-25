import sys
import os

from orchestrator.app import app
from flask_sqlalchemy import SQLAlchemy
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager, Server

host = app.config['HOST']
db_url= app.config['SQLALCHEMY_DATABASE_URI']

db = SQLAlchemy(app)






# default to dev config
env = os.environ.get('WEBAPP_ENV', 'dev')
app = app()

migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command("server", Server())
manager.add_command('db', MigrateCommand)


@manager.shell
def make_shell_context():
    return dict(
        app=app,
        db=db,

    )


if __name__ == "__main__":
    manager.run()
