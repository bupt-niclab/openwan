# from flask_sqlalchemy import SQLAlchemy
# coding:utf-8

# from flask import Flask, url_for
# from flask_restless import APIManager
# from flask_sqlalchemy import SQLAlchemy
# import sqlite3

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///template.sqlite'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
# db = SQLAlchemy(app)

# datafile = 'template.sqlite'
# datadir = ''
# conn = sqlite3.connect(db)

from sqlalchemy import Column, Integer, String, Boolean
from .database import Base


class Probe(Base):
    __tablename__ = 'probe'

    # id = Column(Integer, primary_key=True)
    # title = Column(String(100), nullable=False)
    # content = Column(String(255), nullable=False)
    owner = Column(String(32), primary_key = True)
    test_name = Column(String(32), primary_key = True)
    probe_type = Column(String(3), nullable = True)
    data_fill = Column(String(3), nullable = True)
    data_size = Column(String(5), nullable = True)
    destination_port = Column(String(5), nullable = True)
    dscp_code_point = Column(String(6), nullable = True)
    hardware_time = Column(Boolean, nullable = True)
    history_size = Column(String(3), nullable = True)
    moving_average_size = Column(String(3) , nullable = True)
    probe_count = Column(String(2), nullable = True)
    probe_interval = Column(String(3), nullable = True)
    source_address = Column(String(30), nullable = True)
    target = Column(String(255), nullable = False)
    test_interval = Column(String(5), nullable = False)


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

class Templates(Base):
    __tablename__ = 'templates'

    name = Column(String(32), primary_key = True)
    description = Column(String(255), nullable = True)
    target = Column(String(255), nullable = True)
    function = Column(String(255), nullable = True)
    expr_form = Column(String(255), nullable = True)
    args = Column(String(255), nullable = True)

    def __init__(self,name,description,target,function,expr_form,args):
        self.name = name
        self.description = description
        self.target = target
        self.function = function
        self.expr_form = expr_form
        self.args = args
    
    # def __repr__(self):
    #     return '<name %r, description %r, target %r, function %r, expr_form %r, args %r>' % self.name, % self.description, % self.target, % self.expr_form, % self.function, % self.args

class VPN(Base):
    __tablename__ = 'VPN'

    tid = Column(Integer, primary_key = True, autoincrement = True)
    name = Column(String(255), unique = True)
    LTE_cloudGW = Column(String(30), nullable = False)
    LTE_external_interface = Column(String(30), nullable = False)
    # LTE_internal_interface = Column(String(30),nullable = False)
    LTE_local_identity = Column(String(30),nullable = False)
    LTE_remote_identity = Column(String(30),nullable = False)
    cloud_external_interface = Column(String(30),nullable = False)
    # cloud_internal_interface = Column(String(30),nullable = False)
    cloud_local_address = Column(String(30),nullable = False)
    # network_segment = Column(String(255), nullable = False)
    phase1_dh_group = Column(String(255) , nullable = False)
    phase1_authentication_algorithm = Column(String(30), nullable = False)
    phase1_encryption_algorithm =Column(String(30), nullable = False)
    phase1_pre_shared_key = Column(String(30), nullable = False)
    phase1_dead_peer_detection_nterval = Column(String(30), nullable = False)
    phase1_dead_peer_detection_threshold = Column(String(30),nullable = False)
    # ipsec_protocol = Column(String(30), nullable = False)
    phase2_authentication_algorithm = Column(String(30), nullable = False)
    phase2_encryption_algorithm =Column(String(30), nullable = False)
    phase2_perfect_forward_secrecy_keys = Column(String(30),nullable = False)
    
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





class UTM(Base):
    __tablename__ = 'UTM'

    tid = Column(Integer, primary_key = True, autoincrement = True)
    name = Column(String(255), unique = True)
    content_filtering = Column(String(30),nullable = False)

    anti_virus = Column(String(30),nullable = False)
    antivirus_http = Column(String(30),nullable = False)
    antivirus_smtp = Column(String(30),nullable = False)
    antivirus_ftp = Column(String(30),nullable = False)
    anti_spam = Column(String(30),nullable = False)    
    antispam_default = Column(String(30),nullable = False)
    antispam_custom = Column(String(30),nullable = False)
    
    # black_list_value = Column(String(300),nullable = False)
    spam_black_list_value = Column(String(300),nullable = False)
    spam_black_list_pattern_name = Column(String(30),nullable = False)
    spam_white_list_value = Column(String(300),nullable = False)
    spam_white_list_pattern_name = Column(String(30),nullable = False)
    spam_action = Column(String(30),nullable = False)
    custom_tag_string = Column(String(300),nullable = False)
    sbl_profile_name = Column(String(50),nullable = False)

    

    url_filtering = Column(String(30),nullable = False)
    url_black_list_value = Column(String(300),nullable = False)
    url_black_list_pattern_name = Column(String(30),nullable = False)
    url_black_list_category_name = Column(String(50),nullable = False)
    url_black_list_action = Column(String(30),nullable = False)
    url_white_list_value = Column(String(300),nullable = False)
    url_white_list_pattern_name = Column(String(30),nullable = False)
    url_white_list_category_name = Column(String(30),nullable = False)
    url_white_list_action = Column(String(50),nullable = False)

    fallback_setting_default = Column(String(30),nullable = False)
    fallback_setting_server_connectivity = Column(String(30),nullable = False)
    fallback_setting_timeout = Column(String(30),nullable = False)
    fallback_setting_too_many_requests = Column(String(30),nullable = False)
    url_filtering_name = Column(String(30),nullable = False)


    file_ext_name = Column(String(30),nullable = False)
    file_ext_val = Column(String(300),nullable = False)
    mine_name = Column(String(30),nullable = False)
    mine_val = Column(String(300),nullable = False)
    ex_mine_name = Column(String(30),nullable = False)
    ex_mine_val = Column(String(300), nullable = False)
    confilter_name = Column(String(30),nullable = False)
    block_contype = Column(String(30),nullable = False)

    old_status = Column(String(30),nullable = False)
    old_policy_name = Column(String(30),nullable = False)
    old_src_zone = Column(String(30),nullable = False)
    old_dst_zone = Column(String(30),nullable = False)


    src_zone = Column(String(30),nullable = False)
    dst_zone = Column(String(30),nullable = False)
    src_address = Column(String(30),nullable = False)
    dst_address = Column(String(30),nullable = False)
    new_policy_name = Column(String(30),nullable = False)

    def __init__(self,name,content_filtering,anti_virus,antivirus_http,antivirus_smtp,
    antivirus_ftp,anti_spam,antispam_custom,spam_black_list_value,spam_black_list_pattern_name,
    spam_white_list_value,spam_white_list_pattern_name,spam_action,custom_tag_string,
    sbl_profile_name,antispam_default,url_filtering,url_black_list_value,url_black_list_pattern_name,
    url_black_list_category_name,url_black_list_action,url_white_list_value,url_white_list_pattern_name,
    url_white_list_category_name,url_white_list_action,fallback_setting_default,fallback_setting_server_connectivity,
    fallback_setting_timeout,fallback_setting_too_many_requests,url_filtering_name,file_ext_name,file_ext_val,
    mine_name,mine_val,ex_mine_name,ex_mine_val,confilter_name,block_contype,old_status,old_policy_name,old_src_zone,old_dst_zone,
    src_zone,dst_zone,src_address,dst_address,new_policy_name):
        self.name = name
        self.content_filtering = content_filtering
        self.anti_virus = anti_virus
        self.antivirus_http = antivirus_http
        self.antivirus_smtp = antivirus_smtp
        self.antivirus_ftp = antivirus_ftp
        self.anti_spam = anti_spam
        self.antispam_custom = antispam_custom
        self.spam_black_list_value = spam_black_list_value
        self.spam_black_list_pattern_name = spam_black_list_pattern_name
        self.spam_white_list_value = spam_white_list_value
        self.spam_white_list_pattern_name = spam_white_list_pattern_name
        self.spam_action = spam_action
        self.custom_tag_string = custom_tag_string
        self.sbl_profile_name = sbl_profile_name
        self.antispam_default = antispam_default
        self.url_filtering = url_filtering
        self.url_black_list_value = url_black_list_value
        self.url_black_list_pattern_name = url_black_list_pattern_name
        self.url_black_list_category_name = url_black_list_category_name
        self.url_black_list_action = url_black_list_action
        self.url_white_list_value = url_white_list_value
        self.url_white_list_pattern_name = url_white_list_pattern_name
        self.url_white_list_category_name = url_white_list_category_name
        self.url_white_list_action = url_white_list_action
        self.fallback_setting_default = fallback_setting_default
        self.fallback_setting_server_connectivity = fallback_setting_server_connectivity
        self.fallback_setting_timeout = fallback_setting_timeout
        self.fallback_setting_too_many_requests = fallback_setting_too_many_requests
        self.url_filtering_name = url_filtering_name
        self.file_ext_name = file_ext_name
        self.file_ext_val = file_ext_val
        self.mine_name = mine_name
        self.mine_val = mine_val
        self.ex_mine_name = ex_mine_name
        self.ex_mine_val = ex_mine_val
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






