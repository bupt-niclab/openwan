from flask_sqlalchemy import SQLAlchemy
# coding:utf-8

from flask import Flask, url_for
# from flask_restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
# from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///template.sqlite'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
db = SQLAlchemy(app)

# datafile = 'template.sqlite'
# datadir = ''
# conn = sqlite3.connect(db)

# from sqlalchemy import create_engine
# from sqlalchemy.orm import scoped_session, sessionmaker
# from sqlalchemy.ext.declarative import declarative_base


# engine = create_engine('sqlite:///template.sqlite', convert_unicode=True)
# db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False,bind=engine))
# Base = declarative_base()
# Base.query = db_session.query_property()

# def init_db():
#     from . import models
#     Base.metadata.create_all(bind=engine)



class VPN(db.Model):
    __tablename__ = 'VPN'

    tid = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(255), unique = True)
    LTE_cloudGW = db.Column(db.String(30), nullable = False)
    LTE_external_interface = db.Column(db.String(30), nullable = False)
    # LTE_internal_interface = db.Column(db.String(30),nullable = False)
    LTE_local_identity = db.Column(db.String(30),nullable = False)
    LTE_remote_identity = db.Column(db.String(30),nullable = False)
    cloud_external_interface = db.Column(db.String(30),nullable = False)
    # cloud_internal_interface = db.Column(db.String(30),nullable = False)
    cloud_local_address = db.Column(db.String(30),nullable = False)
    # network_segment = Column(String(255), nullable = False)
    phase1_dh_group = db.Column(db.String(255) , nullable = False)
    phase1_authentication_algorithm = db.Column(db.String(30), nullable = False)
    phase1_encryption_algorithm =db.Column(db.String(30), nullable = False)
    phase1_pre_shared_key = db.Column(db.String(30), nullable = False)
    phase1_dead_peer_detection_nterval = db.Column(db.String(30), nullable = False)
    phase1_dead_peer_detection_threshold = db.Column(db.String(30),nullable = False)
    # ipsec_protocol = Column(String(30), nullable = False)
    phase2_authentication_algorithm = db.Column(db.String(30), nullable = False)
    phase2_encryption_algorithm =db.Column(db.String(30), nullable = False)
    phase2_perfect_forward_secrecy_keys = db.Column(db.String(30),nullable = False)

    def __init__(self,name,LTE_cloudGW,LTE_external_interface,LTE_local_identity,LTE_remote_identity,
    cloud_external_interface,cloud_local_address,
    phase1_dh_group,phase1_authentication_algorithm,phase1_encryption_algorithm,phase1_pre_shared_key,
    phase1_dead_peer_detection_nterval,phase1_dead_peer_detection_threshold,
    phase2_authentication_algorithm,phase2_encryption_algorithm,phase2_perfect_forward_secrecy_keys):
        # self.tid = tid
        self.name = name
        self.LTE_cloudGW = LTE_cloudGW
        self.LTE_external_interface = LTE_external_interface
        # self.LTE_internal_interface = LTE_internal_interface
        self.LTE_local_identity = LTE_local_identity
        self.LTE_remote_identity = LTE_remote_identity
        self.cloud_external_interface = cloud_external_interface
        # self.cloud_internal_interface = cloud_internal_interface
        self.cloud_local_address = cloud_local_address
        # self.network_segment = network_segment
        self.phase1_dh_group = phase1_dh_group
        self.phase1_authentication_algorithm = phase1_authentication_algorithm
        self.phase1_encryption_algorithm = phase1_encryption_algorithm
        self.phase1_pre_shared_key = phase1_pre_shared_key
        self.phase1_dead_peer_detection_nterval = phase1_dead_peer_detection_nterval
        self.phase1_dead_peer_detection_threshold = phase1_dead_peer_detection_threshold
        self.phase2_authentication_algorithm = phase2_authentication_algorithm
        self.phase2_encryption_algorithm = phase2_encryption_algorithm
        self.phase2_perfect_forward_secrecy_keys=phase2_perfect_forward_secrecy_keys
    
    def __repr__(self):
        return '<name %r>' % self.name

# class UTM(db.Model):
#     __tablename__ = 'UTM'

#     tid = db.Column(db.Integer, primary_key = True, autoincrement = True)
#     name = db.Column(db.String(255), unique = True)
#     content_filtering = db.Column(db.String(30),nullable = False)

#     anti_virus = db.Column(db.String(30),nullable = False)
#     antivirus_http = db.Column(db.String(30),nullable = False)
#     antivirus_smtp = db.Column(db.String(30),nullable = False)
#     antivirus_ftp = db.Column(db.String(30),nullable = False)
#     anti_spam = db.Column(db.String(30),nullable = False)    
#     antispam_default = db.Column(db.String(30),nullable = False)
#     antispam_custom = db.Column(db.String(30),nullable = False)
    
#     # black_list_value = Column(String(300),nullable = False)
#     spam_black_list_value = db.Column(db.String(300),nullable = False)
#     spam_black_list_pattern_name = db.Column(db.String(30),nullable = False)
#     spam_white_list_value = db.Column(db.String(300),nullable = False)
#     spam_white_list_pattern_name = db.Column(db.String(30),nullable = False)
#     spam_action = db.Column(db.String(30),nullable = False)
#     custom_tag_string = db.Column(db.String(300),nullable = False)
#     sbl_profile_name = db.Column(db.String(50),nullable = False)

    

#     url_filtering =db.Column(db.String(30),nullable = False)
#     url_black_list_value = db.Column(db.String(300),nullable = False)
#     url_black_list_pattern_name = db.Column(db.String(30),nullable = False)
#     url_black_list_category_name = db.Column(db.String(50),nullable = False)
#     url_black_list_action = db.Column(db.String(30),nullable = False)
#     url_white_list_value = db.Column(db.String(300),nullable = False)
#     url_white_list_pattern_name = db.Column(db.String(30),nullable = False)
#     url_white_list_category_name = db.Column(db.String(30),nullable = False)
#     url_white_list_action = db.Column(db.String(50),nullable = False)

#     fallback_setting_default = db.Column(db.String(30),nullable = False)
#     fallback_setting_server_connectivity = db.Column(db.String(30),nullable = False)
#     fallback_setting_timeout = db.Column(db.String(30),nullable = False)
#     fallback_setting_too_many_requests = db.Column(db.String(30),nullable = False)
#     url_filtering_name = db.Column(db.String(30),nullable = False)


#     file_ext_name = db.Column(db.String(30),nullable = False)
#     file_ext_val = db.Column(db.String(300),nullable = False)
#     mine_name = db.Column(db.String(30),nullable = False)
#     mine_val = db.Column(db.String(300),nullable = False)
#     ex_mine_name = db.Column(db.String(30),nullable = False)
#     ex_mine_val = db.Column(db.String(300), nullable = False)
#     confilter_name = db.Column(db.String(30),nullable = False)
#     block_contype = db.Column(db.String(30),nullable = False)

#     old_status = db.Column(db.String(30),nullable = False)
#     old_policy_name = db.Column(db.String(30),nullable = False)
#     old_src_zone = db.Column(db.String(30),nullable = False)
#     old_dst_zone = db.Column(db.String(30),nullable = False)


#     src_zone = db.Column(db.String(30),nullable = False)
#     dst_zone = db.Column(db.String(30),nullable = False)
#     src_address = db.Column(db.String(30),nullable = False)
#     dst_address = db.Column(db.String(30),nullable = False)
#     new_policy_name = db.Column(db.String(30),nullable = False)

#     def __init__(self,name,content_filtering,anti_virus,antivirus_http,antivirus_smtp,
#     antivirus_ftp,anti_spam,antispam_custom,spam_black_list_value,spam_black_list_pattern_name,
#     spam_white_list_value,spam_white_list_pattern_name,spam_action,custom_tag_string,
#     sbl_profile_name,antispam_default,url_filtering,url_black_list_value,url_black_list_pattern_name,
#     url_black_list_category_name,url_black_list_action,url_white_list_value,url_white_list_pattern_name,
#     url_white_list_category_name,url_white_list_action,fallback_setting_default,fallback_setting_server_connectivity,
#     fallback_setting_timeout,fallback_setting_too_many_requests,url_filtering_name,file_ext_name,file_ext_val,
#     mine_name,mine_val,ex_mine_name,ex_mine_val,confilter_name,block_contype,old_status,old_policy_name,old_src_zone,old_dst_zone,
#     src_zone,dst_zone,src_address,dst_address,new_policy_name):
#         self.name = name
#         self.content_filtering = content_filtering
#         self.anti_virus = anti_virus
#         self.antivirus_http = antivirus_http
#         self.antivirus_smtp = antivirus_smtp
#         self.antivirus_ftp = antivirus_ftp
#         self.anti_spam = anti_spam
#         self.antispam_custom = antispam_custom
#         self.spam_black_list_value = spam_black_list_value
#         self.spam_black_list_pattern_name = spam_black_list_pattern_name
#         self.spam_white_list_value = spam_white_list_value
#         self.spam_white_list_pattern_name = spam_white_list_pattern_name
#         self.spam_action = spam_action
#         self.custom_tag_string = custom_tag_string
#         self.sbl_profile_name = sbl_profile_name
#         self.antispam_default = antispam_default
#         self.url_filtering = url_filtering
#         self.url_black_list_value = url_black_list_value
#         self.url_black_list_pattern_name = url_black_list_pattern_name
#         self.url_black_list_category_name = url_black_list_category_name
#         self.url_black_list_action = url_black_list_action
#         self.url_white_list_value = url_white_list_value
#         self.url_white_list_pattern_name = url_white_list_pattern_name
#         self.url_white_list_category_name = url_white_list_category_name
#         self.url_white_list_action = url_white_list_action
#         self.fallback_setting_default = fallback_setting_default
#         self.fallback_setting_server_connectivity = fallback_setting_server_connectivity
#         self.fallback_setting_timeout = fallback_setting_timeout
#         self.fallback_setting_too_many_requests = fallback_setting_too_many_requests
#         self.url_filtering_name = url_filtering_name
#         self.file_ext_name = file_ext_name
#         self.file_ext_val = file_ext_val
#         self.mine_name = mine_name
#         self.mine_val = mine_val
#         self.ex_mine_name = ex_mine_name
#         self.ex_mine_val = ex_mine_val
#         self.confilter_name = confilter_name
#         self.block_contype = block_contype
#         self.old_status = old_status
#         self.old_policy_name = old_policy_name
#         self.old_src_zone = old_src_zone
#         self.old_dst_zone = old_dst_zone
#         self.src_zone = src_zone
#         self.dst_zone = dst_zone
#         self.src_address = src_address
#         self.dst_address = dst_address
#         self.new_policy_name = new_policy_name

#     def __repr__(self):
#         return '<name %r>' % self.name


class UTM(db.Model):
    __tablename__ = 'UTM'

    tid = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(255), unique = True)
    content_filtering = db.Column(db.String(30),nullable = False)

    anti_virus = db.Column(db.String(30),nullable = False)
    anti_spam = db.Column(db.String(30),nullable = False)    
    antispam_default = db.Column(db.String(30),nullable = False)
    antispam_custom = db.Column(db.String(30),nullable = False)
    
    spam_black_list_value = db.Column(db.String(300),nullable = True)
    spam_black_list_pattern_name = db.Column(db.String(30),nullable = True)
    spam_action = db.Column(db.String(30),nullable = True)
    sbl_profile_name = db.Column(db.String(50),nullable = True)

    url_filtering = db.Column(db.String(30),nullable = False)
    url_black_list_value = db.Column(db.String(300),nullable = True)
    url_black_list_pattern_name = db.Column(db.String(30),nullable = True)
    url_black_list_category_name = db.Column(db.String(50),nullable = True)
    url_black_list_action = db.Column(db.String(30),nullable = True)
    url_filtering_name = db.Column(db.String(30),nullable = True)


    confilter_name = db.Column(db.String(30),nullable = True)
    block_contype = db.Column(db.String(30),nullable = True)

    old_status = db.Column(db.String(30),nullable = False)
    old_policy_name = db.Column(db.String(30),nullable = False)
    old_src_zone = db.Column(db.String(30),nullable = False)
    old_dst_zone = db.Column(db.String(30),nullable = False)

    src_zone = db.Column(db.String(30),nullable = False)
    dst_zone = db.Column(db.String(30),nullable = False)
    src_address = db.Column(db.String(30),nullable = False)
    dst_address = db.Column(db.String(30),nullable = False)
    new_policy_name = db.Column(db.String(30),nullable = False)

    def __init__(self,name,content_filtering,anti_virus,antispam_default,
    anti_spam,antispam_custom,spam_black_list_value,spam_black_list_pattern_name,
    spam_action,sbl_profile_name,url_filtering,
    url_black_list_value,url_black_list_pattern_name,
    url_black_list_category_name,url_black_list_action,
    url_filtering_name,
    confilter_name,block_contype,old_status,old_policy_name,old_src_zone,old_dst_zone,
    src_zone,dst_zone,src_address,dst_address,new_policy_name):
        self.name = name
        self.content_filtering = content_filtering
        self.anti_virus = anti_virus
        self.anti_spam = anti_spam
        self.antispam_default = antispam_default
        self.antispam_custom = antispam_custom
        self.spam_black_list_value = spam_black_list_value
        self.spam_black_list_pattern_name = spam_black_list_pattern_name

        self.spam_action = spam_action
        self.sbl_profile_name = sbl_profile_name
        
        self.url_filtering = url_filtering
        self.url_black_list_value = url_black_list_value
        self.url_black_list_pattern_name = url_black_list_pattern_name
        self.url_black_list_category_name = url_black_list_category_name
        self.url_black_list_action = url_black_list_action

        self.url_filtering_name = url_filtering_name

        self.confilter_name = confilter_name
        self.block_contype = block_contype
        self.old_status = old_status
        self.old_policy_name = old_policy_name
        self.old_src_zone = old_src_zone
        self.old_dst_zone = old_dst_zone
        self.src_zone = src_zone
        self.dst_zone = dst_zone
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_policy_name = new_policy_name

    def __repr__(self):
        return '<name %r>' % self.name

class IDP(db.Model):
    __tablename__ = 'IDP'
    
    tid = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(255), unique = True)
    idp_rule_name = db.Column(db.String(300), nullable = True)
    rule_src_zone = db.Column(db.String(30), nullable = False)
    rule_dst_zone = db.Column(db.String(30), nullable = False)
    idprule_action = db.Column(db.String(30),nullable = False)
    idprule_sev = db.Column(db.String(30), nullable = False)
    predefine_idp = db.Column(db.String(30), nullable = False)
    custom_idp = db.Column(db.String(30), nullable = False)
    cus_attack_name = db.Column(db.String(300), nullable = True)
    cus_attack_serverity = db.Column(db.String(30), nullable = True)
    cus_attack_action = db.Column(db.String(30), nullable = True)
    cus_attack_direction = db.Column(db.String(30), nullable = True)

    old_status = db.Column(db.String(30),nullable = False)
    old_policy_name = db.Column(db.String(30),nullable = False)
    old_src_zone = db.Column(db.String(30),nullable = False)
    old_dst_zone = db.Column(db.String(30),nullable = False)

    src_zone = db.Column(db.String(30),nullable = False)
    dst_zone = db.Column(db.String(30),nullable = False)
    src_address = db.Column(db.String(30),nullable = False)
    dst_address = db.Column(db.String(30),nullable = False)
    new_policy_name = db.Column(db.String(30),nullable = False)

    def __init__(self, tid, name,idp_rule_name, rule_src_zone, rule_dst_zone, 
    idprule_action, idprule_sev, predefine_idp, custom_idp,
    cus_attack_name, cus_attack_serverity, cus_attack_action, cus_attack_direction,
    old_status, old_policy_name, old_src_zone, old_dst_zone,
    src_zone, dst_zone, src_address, dst_address, new_policy_name):
        self.name = name
        self.idp_rule_name = idp_rule_name
        self.rule_src_zone = rule_src_zone
        self.rule_dst_zone = rule_dst_zone
        self.idprule_action = idprule_action
        self.idprule_sev = idprule_sev
        self.predefine_idp = predefine_idp
        self.custom_idp = custom_idp
        self.cus_attack_name = cus_attack_name
        self.cus_attack_serverity = cus_attack_serverity
        self.cus_attack_action = cus_attack_action
        self.cus_attack_direction = cus_attack_direction
        self.old_status = old_status
        self.old_policy_name = old_policy_name
        self.old_src_zone = old_src_zone
        self.old_dst_zone = old_dst_zone
        self.src_zone = src_zone
        self.dst_zone = dst_zone
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_policy_name = new_policy_name

    def __repr__(self):
        return '<name %r>' % self.name
