from flask_sqlalchemy import SQLAlchemy
# coding:utf-8

from flask import Flask, url_for
# from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///template.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
db = SQLAlchemy(app)

# datafile = 'template.sqlite'
# datadir = ''
# conn = sqlite3.connect(db)

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base


engine = create_engine('sqlite:///template.sqlite', convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False,bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    from . import models
    Base.metadata.create_all(bind=engine)



class VPN(Base):
    __tablename__ = 'VPN'

    tid = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(255), unique = True)
    LTE_cloudGW = db.Column(db.String(30), nullable = False)
    LTE_external_interface = db.Column(db.dbString(30), nullable = False)
    LTE_internal_interface = db.Column(db.String(30),nullable = False)
    LTE_local_identity = db.Column(db.String(30),nullable = False)
    LTE_remote_identity = db.Column(db.String(30),nullable = False)
    cloud_external_interface = db.Column(db.String(30),nullable = False)
    cloud_internal_interface = db.Column(db.String(30),nullable = False)
    cloud_local_address = db.Column(db.String(30),nullable = False)
    # network_segment = Column(String(255), nullable = False)
    dh_group = db.Column(db.String(255) , nullable = False)
    authentication_algorithm = db.Column(db.String(30), nullable = False)
    encryption_algorithm =db.Column(db.String(30), nullable = False)
    pre_shared_key = db.Column(db.String(30), nullable = False)
    # ipsec_protocol = Column(String(30), nullable = False)

    def __init__(self,name,LTE_cloudGW,LTE_external_interface,LTE_internal_interface,
    LTE_local_identity,LTE_remote_identity,cloud_external_interface,cloud_internal_interface,
    cloud_local_address,dh_group,authentication_algorithm,encryption_algorithm,pre_shared_key):
        # self.tid = tid
        self.name = name
        self.LTE_cloudGW = LTE_cloudGW
        self.LTE_external_interface = LTE_external_interface
        self.LTE_internal_interface = LTE_internal_interface
        self.LTE_local_identity = LTE_local_identity
        self.cloud_external_interface = cloud_external_interface
        self.cloud_internal_interface = cloud_internal_interface
        self.cloud_local_address = cloud_local_address
        # self.network_segment = network_segment
        self.dh_group = dh_group
        self.authentication_algorithm = authentication_algorithm
        self.encryption_algorithm = encryption_algorithm
        self.pre_shared_key = pre_shared_key
        self.ipsec_protocol = ipsec_protocol
    
    def __repr__(self):
        return '<name %r>' % self.name
