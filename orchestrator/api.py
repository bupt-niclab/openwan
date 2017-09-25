# coding:utf-8

from flask import Flask, url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///template.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
db = SQLAlchemy(app)


class Templates(db.Model):
    __tablename__ = 'templates'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(255), nullable=False)

    def __unicode__(self):
        return self.content

    def url(self):
        return url_for('.templates', article_id=self.id)


# create the Flask-Restless API manager
manager = APIManager(app, flask_sqlalchemy_db=db)

# create our Article API at /api/articles
manager.create_api(Templates, collection_name='templates', methods=['GET', 'POST', 'PUT', 'DELETE'])

db.create_all()

if __name__ == '__main__':
    # we define the debug environment only if running through command line
    app.config['SQLALCHEMY_ECHO'] = True
    app.debug = True
    app.run()
