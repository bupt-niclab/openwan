from flask_sqlalchemy import SQLAlchemy
# coding:utf-8

from flask import Flask, url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///template.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
db = SQLAlchemy(app)

datafile = 'template.sqlite'
# datadir = ''
conn = sqlite3.connect(db)




class Probe(db.Model):
    __tablename__ = 'probe'

    # id = db.Column(db.Integer, primary_key=True)
    # title = db.Column(db.String(100), nullable=False)
    # content = db.Column(db.String(255), nullable=False)
    owner = db.Column(db.String(32), primary_key = True)
    test_name = db.Column(db.String(32), primary_key = True)
    probe_type = db.Column(db.String(3), nullable = True)
    data_fill = db.Column(db.String(3), nullable = True)
    data_size = db.Column(db.String(5), nullable = True)
    destination_port = db.Column(db.String(5), nullable = True)
    dscp_code_point = db.Column(db.String(6), nullable = True)
    hardware_time = db.Column(db.Boolean, nullable = True)
    history_size = db.Column(db.String(3), nullable = True)
    moving_average_size = db.Column(db.String(3) , nullable = True)
    probe_count = db.Column(db.String(2), nullable = True)
    probe_interval = db.Column(db.String(3), nullable = True)
    source_address = db.Column(db.String(30), nullable = True)
    target = db.Column(db.String(255), nullable = False)
    test_interval = db.Column(db.String(5), nullable = False)


    def __unicode__(self):
        return self.content

    # def url(self):
    #     return url_for('add_http_get_template', article_id=self.id)

    def __init__(self,owner,test_name,probe_type,data_fill,data_size,
    destination_port,dscp_code_point,hardware_time,history_size,moving_average_size,
    probe_count,probe_interval,source_address,target,test_interval):
        self.owner = owner
        self.test_name = test_name
        self.probe_type = probe_type
        self.data_fill = data_fill
        self.data_size = data_size
        self.destination_port = destination_port
        self.dscp_code_point = dscp_code_point
        self.hardware_time = hardware_time
        self.history_size = history_size
        self.moving_average_size = moving_average_size
        self.probe_count = probe_count
        self.probe_interval = probe_interval
        self.source_address = source_address
        self.target = target
        self.test_interval = test_interval
    
    # def __repr__(self):
        # return '<owner %r , test_name %r, target %r, test_interval %r>' % self.owner, % self.test_name, % self.target, % self.test_interval

class Templates(db.Model):
    __tablename__ = 'templates'

    name = db.Column(db.String(32), primary_key = True)
    description = db.Column(db.String(255), nullable = True)
    target = db.Column(db.String(255), nullable = True)
    function = db.Column(db.String(255), nullable = True)
    expr_form = db.Column(db.String(255), nullable = True)
    args = db.Column(db.String(255), nullable = True)

    def __init__(self,name,description,target,function,expr_form,args):
        self.name = name
        self.description = description
        self.target = target
        self.function = function
        self.expr_form = expr_form
        self.args = args
    
    # def __repr__(self):
    #     return '<name %r, description %r, target %r, function %r, expr_form %r, args %r>' % self.name, % self.description, % self.target, % self.expr_form, % self.function, % self.args

class VPN(db.Model):
    __tablename__ = 'VPN'

    name = db.Column(db.String(255), primary_key = True)
    network_segment = db.Column(db.String(255), nullable = False)
    dh_group = db.Column(db.String(255) , nullable = False)
    authentication_algorithm = db.Column(db.String(30), nullable = False)
    encryption_algorithm = db.Column(db.String(30), nullable = False)
    pre_shared_key = db.Column(db.String(30), nullable = False)
    ipsec_protocol = db.Column(db.String(30), nullable = False)

    def __init__(self,name,network_segment,dh_group,authentication_algorithm,encryption_algorithm,pre_shared_key,ipsec_protocol):
        self.name = name
        self.network_segment = network_segment
        self.dh_group = dh_group
        self.authentication_algorithm = authentication_algorithm
        self.encryption_algorithm = encryption_algorithm
        self.pre_shared_key = pre_shared_key
        self.ipsec_protocol = ipsec_protocol
    
    def __repr__(self):
        return '<name %r>' % self.name