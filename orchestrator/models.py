from flask_sqlalchemy import SQLAlchemy
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
