#coding=utf-8

import sys
import json
import os
import socket

from functools import wraps
from six import string_types
from os.path import join, dirname
reload(sys)  # Reload is a hack
sys.setdefaultencoding('UTF8')
from flask import Flask, redirect, render_template, url_for, session, request, flash, jsonify, current_app
# from flask_assets import Environment, Bundle
from .core import HTTPSaltStackClient, ExpiredToken, Unauthorized, JobNotStarted
from .utils import login_url, parse_highstate, NotHighstateOutput, parse_argspec
from .utils import format_arguments, Call, validate_permissions, REQUIRED_PERMISSIONS
from .utils import get_filtered_post_arguments
from flask_admin import Admin
from . import settings
# from flask_sqlalchemy import sqlalchemy
from .database import db_session
from models import Templates, VPN, Probe, UTM
from jinja2 import select_autoescape, Template
# from models import db
# from flask.ext.sqlalchemy import sqlalchemy

# global lastapply_tid = False
LASTAPPLY_TID = 0
LASTAPPLY_UTM = 0
LASTAPPLY_IDP = 0

# Init app


class FlaskHTTPSaltStackClient(HTTPSaltStackClient):
    def get_token(self):
        return session.get('user_token')


template_folder = join(dirname(__file__), 'templates')
static_folder = join(dirname(__file__), 'static')
app = Flask(
    "Controller", template_folder=template_folder, static_folder=static_folder)
app.config.from_object(settings)
admin = Admin()
# Setup logging
if not app.debug:
    from logging import FileHandler
    app.logger.addHandler(FileHandler(app.config['LOG_FILE']))

# Setup sentry
try:
    from raven.contrib.flask import Sentry
    if app.config.get('SENTRY_DSN'):
        sentry = Sentry(app, dsn=app.config['SENTRY_DSN'])
except ImportError:
    if app.config.get('SENTRY_DSN'):
        install_cmd = "pip install raven[flask]"
        print(
            "Couldn't import raven, please install it with '%s'" % install_cmd)
        sys.exit(1)

# Flask assets
from flask_assets import Environment, Bundle
from webassets.filter import get_filter
assets = Environment(app)

cssrewrite = get_filter(
    'cssrewrite', replace={
        '../': '../vendor/font--awesome/'
    })

bundles = {
    'base_js':
    Bundle(
        'vendor/jquery/jquery.min.js',
        'vendor/bootstrap/js/bootstrap.min.js',
        'vendor/metisMenu/metisMenu.min.js',
        'js/jsontree.js',
        'js/jquery.dataTables.min.js',
        'js/dataTables.bootstrap.js',
        'js/fastclick.min.js',                
        'js/control-admin-2.js',
        filters='jsmin',
        output='gen/packed.js'),
    'traffic_path_js':
    Bundle(
        'js/jtopo-0.4.8-min.js',
        'js/topo.js',
        filters='jsmin',
        output='gen/traffic_path.js'),
    'control_path_js':
    Bundle(
        'js/jtopo-0.4.8-min.js',
        'js/control_topo.js',
        'js/jquery.loading.min.js',
        'js/jquery-confirm.min.js',        
        filters='jsmin',
        output='gen/control_path.js'),
    'health_checks_js': 
    Bundle(
        'js/echarts.simple.min.js',
        'js/health_checks.js',
        filters='jsmin',
        output='gen/health_checks.js'),
    'base_css':
    Bundle(
        'vendor/bootstrap/css/bootstrap.css',
        'css/control-admin-2.css',
        'vendor/font-awesome/css/font-awesome.min.css',
        'css/jsontree.css',
        'css/dataTables.bootstrap.css',
        'css/jquery.loading.min.css',
        'css/jquery-confirm.min.css',
        filters='cssmin, cssrewrite',
        output='gen/packed.css')
}

assets.register(bundles)

# Flask Babel
from flask_babel import Babel, gettext as _
app.config['BABEL_DEFAULT_LOCALE'] = 'zh_Hans_CN'
babel = Babel(app)

client = FlaskHTTPSaltStackClient(app.config['API_URL'],
                                  app.config.get('VERIFY_SSL', True))

from flask_wtf import FlaskForm as Form
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError


class LoginForm(Form):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get('user_token'):
            return redirect(login_url('login', request.url))

        try:
            return view(*args, **kwargs)
        except (ExpiredToken, Unauthorized):
            return redirect(login_url('login', request.url))

    return wrapper


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user_token = client.login(form['username'].data,
                                      form['password'].data)
            if not validate_permissions(user_token['perms']):
                perms = REQUIRED_PERMISSIONS
                msg = 'Invalid permissions,It needs {0} for user {1}'.format(
                    perms, form['username'].data)
                flash(msg, 'error')
            else:
                session['username'] = form['username'].data
                session['user_token'] = user_token['token']
                flash('Hi {0}'.format(form['username'].data))
                return redirect(request.args.get("next") or url_for("index"))
        except Unauthorized:
            flash('Invalid credentials', 'error')

    return render_template("login.html", form=form)


@app.route('/logout', methods=["GET"])
def logout():
    session.clear()
    flash('Bye!')
    return redirect(url_for('login'))


@app.route("/")
@login_required
def index():
    minions = client.minions_status()
    sync_status = {}
    sync_number = 0

    jobs = sorted(list(client.jobs().items()), reverse=True)[:10]

    return render_template(
        'dashboard.html', minions=minions, ok_status=sync_number, jobs=jobs)


@app.route("/minions")
@login_required
def minions_status():
    minions = client.minions()
    minions_status = client.minions_status()

    for minion in minions_status['up']:
        minions.setdefault(minion, {})['state'] = 'up'

    for minion in minions_status['down']:
        minions.setdefault(minion, {})['state'] = 'down'

    jobs = client.select_jobs(
        'state.highstate',
        minions,
        with_details=True,
        test=True,
        default_arguments_values={
            'test': False
        })

    return render_template('minions.html', minions=minions, jobs=jobs)


@app.route("/minions_deployments")
@login_required
def minions_deployments():
    minions = client.minions()
    minions_status = client.minions_status()

    for minion in minions_status['up']:
        minions.setdefault(minion, {})['state'] = 'up'

    for minion in minions_status['down']:
        minions.setdefault(minion, {})['state'] = 'down'

    jobs = client.select_jobs(
        'state.highstate',
        minions,
        with_details=True,
        test=False,
        default_arguments_values={
            'test': False
        })

    return render_template(
        'minions_deployments.html', minions=minions, jobs=jobs)


@app.route("/minions/<minion>/do_deploy")
@login_required
def minions_do_deploy(minion):
    jid = client.run(
        'state.highstate', client="local_async", tgt=minion)['jid']
    return redirect(
        url_for('job_result', minion=minion, jid=jid, renderer='highstate'))


@app.route("/minions/<minion>/do_check_sync")
@login_required
def minions_do_check_sync(minion):
    jid = client.run(
        'state.highstate',
        client="local_async",
        tgt=minion,
        args=Call(test=True))['jid']
    return redirect(
        url_for('job_result', minion=minion, jid=jid, renderer='highstate'))

@app.route("/jobs")
@login_required
def jobs():
    jobs = sorted(list(client.jobs().items()), reverse=True)
    return render_template('jobs.html', jobs=jobs)


@app.route("/job_result/<jid>")
@login_required
def job_result(jid):
    minion = request.args.get('minion', None)
    renderer = request.args.get('renderer', 'raw')
    job = client.job(jid)

    context = {}

    if renderer == 'highstate':
        try:
            job = parse_highstate(job)
        except NotHighstateOutput:
            return redirect(
                url_for('job_result', jid=jid, minion=minion, renderer='raw'))
    elif renderer == 'aggregate':
        aggregate_result = {}

        for minion, minion_return in job['return'].items():
            aggregate_result.setdefault(str(minion_return), []).append(minion)

        missing_minions = set(job['info']['Minions']) - set(
            job['return'].keys())
        if missing_minions:
            aggregate_result['Missing results'] = missing_minions
        job['aggregate_return'] = aggregate_result
        context['total_minions'] = sum(
            len(minions) for minions in aggregate_result.values())

    if not job:
        return "Unknown jid", 404
    return render_template(
        'job_result_{0}.html'.format(renderer),
        job=job,
        minion=minion,
        renderer=renderer,
        **context)


@app.route("/templates")
@login_required
def templates():
    # master_config = client.run('config.values', client="wheel")['data']['return']
    # if not master_config.get('templates'):
    #     master_config['templates'] = {}
    vpn_tmp = db_session.query(VPN).all()
    utm_tmp = db_session.query(UTM).all()

    # return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))

    return render_template(
        "templates.html", vpn_templates=vpn_tmp, utm_templates=utm_tmp)


# @app.route("/api_templates/<switchname>")
# # @login_required
# def api_templates(switchname):
#     global LASTAPPLY_TID
#     tmp = db_session.query(VPN).all()
#     tmp_dict = VPN2dict(tmp)
#     for t in tmp_dict:
#         if t['tid'] == LASTAPPLY_TID:
#             t['applied'] = True
#         else:
#             t['applied'] = False
#     # data = VPN2dict(tmp)
#     # data[0]['applied'] = True
#     return jsonify(errmsg="success", data=tmp_dict)


@app.route("/templates/run/<template>")
@login_required
def run_template(template):
    master_config = client.run(
        'config.values', client="wheel")['data']['return']
    template_data = master_config['templates'].get(template)

    if not template_data:
        return "Unknown template", 404

    jid = client.run(
        template_data['fun'],
        client="local_async",
        tgt=template_data['tgt'],
        expr_form=template_data['expr_form'],
        args=Call(**template_data['args']))['jid']

    return redirect(url_for('job_result', jid=jid))


@app.route("/templates/new", methods=['GET', 'POST'])
# @login_required
def add_template():
    vpn_form = VPNForm()
    utm_form = UTMForm()
    idp_form = IDPForm()
    #获取utm数据库数据的条目数量
    utm_num = db_session.query(UTM).count() 
    utm_num = utm_num + 1
    print("utm num is ",utm_num)
    utm_name = "Basic_UTM_" + str(utm_num) 
    print("utm name should be ",utm_name)
    utm_spam_black_list_pattern_name = "url_black_" + str(utm_num) 
    utm_sbl_profile_name = "antispam_sblpro_" + str(utm_num) 
    utm_url_black_list_pattern_name = "url_black_" + str(utm_num)  + str(utm_num) 
    utm_url_black_list_category_name = "url_category_black_" + str(utm_num) 
    utm_url_filtering_name = "surfprofile_" + str(utm_num) 
    utm_confilter_name = "confilter_profile_" + str(utm_num) 
    utm_new_policy_name = "Client_Outbound_" + str(utm_num) 
    utm_old_policy_name = "Client-Outbound-3,untrust,trust"
    print('post 1')  

    

    # # 获取旧的policy
    # ff = subprocess("salt '*' test.ping",shell = True)
    # f = subprocess("salt LTE-node2-agent junos.rpc 'get-firewall-policies'",shell = True)
    
    # for line in f:
    #     if 'policy_name' in line:
    #         d = dict()
    #         str_name = line.strip().strip(':')
    #         print(str_name)
    #         str_command = "salt LTE-node2-agent junos.rpc 'get-firewall-policies' policy-name="+ str_name 
    #         command = subprocess(str_command,shell = True)
    #         for l in command:
    #             if 'destination-zone-name' in l:
    #                 str_name = str_name +","+ l.strip().strip(':')
    #                 print(str_name)
    #             if 'source-zone-name' in l:
    #                 str_name = str_name + ","+ l.strip().strip(':')
    #                 print(str_name)
    #         d[str_name] = str_name
    #         utm_old_policy_name = str_name
    #         old_policy_name.append(d)
    
    if vpn_form.validate_on_submit():
        print('post 2') 
                
        # ((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))/24
        tmp = VPN(vpn_form.name.data, vpn_form.LTE_cloudGW.data,
                  vpn_form.LTE_external_interface.data,
                  vpn_form.LTE_local_identity.data,
                  vpn_form.LTE_remote_identity.data,
                  vpn_form.cloud_external_interface.data,
                  vpn_form.cloud_local_address.data,
                  vpn_form.phase1_dh_group.data,
                  vpn_form.phase1_authentication_algorithm.data,
                  vpn_form.phase1_encryption_algorithm.data,
                  vpn_form.phase1_pre_shared_key.data,
                  vpn_form.phase1_dead_peer_detection_nterval.data,
                  vpn_form.phase1_dead_peer_detection_threshold.data,
                  vpn_form.phase2_authentication_algorithm.data,
                  vpn_form.phase2_encryption_algorithm.data,
                  vpn_form.phase2_perfect_forward_secrecy_keys.data)

        db_session.add(tmp)
        db_session.commit()
        flash('template saved successfully')
        return redirect(url_for('templates'))
    if utm_form.validate_on_submit():
        print('post 3')    
        utm_form.name.data = utm_name
        utm_form.spam_black_list_pattern_name.data = utm_spam_black_list_pattern_name
        utm_form.sbl_profile_name.data = utm_sbl_profile_name
        utm_form.url_black_list_pattern_name.data = utm_url_black_list_pattern_name
        utm_form.url_black_list_category_name.data = utm_url_black_list_category_name
        utm_form.url_filtering_name.data = utm_url_filtering_name
        utm_form.confilter_name.data = utm_confilter_name
        utm_form.new_policy_name.data = utm_new_policy_name
        utm_form.old_policy_name.data = utm_old_policy_name.split(',')[0]
        utm_form.old_dst_zone.data = utm_old_policy_name.split(',')[1]
        utm_form.old_src_zone.data = utm_old_policy_name.split(',')[2]
        tmp = UTM(utm_form.anti_virus.data,
                  utm_form.content_filtering.data,
                  utm_form.anti_virus.data,
                  utm_form.anti_spam.data,
                  utm_form.antispam_default.data,
                  utm_form.antispam_custom.data,
                  utm_form.spam_black_list_value.data,
                  # utm_form.spam_black_list_pattern_name.data,
                  utm_form.spam_action.data,
                  utm_form.url_filtering.data,
                  utm_form.url_black_list_value.data,
                  utm_form.url_black_list_action.data,
                  utm_form.old_status.data,
                #   utm_form.old_policy_name.data,
                #   utm_form.old_src_zone.data,
                #   utm_form.old_dst_zone.data,
                  utm_form.src_zone.data,
                  utm_form.dst_zone.data,
                  utm_form.src_address.data,
                  utm_form.dst_address.data,

                  utm_form.name.data,
                  utm_form.spam_black_list_pattern_name.data,
                  utm_form.sbl_profile_name.data,
                  utm_form.url_black_list_pattern_name.data,
                  utm_form.url_black_list_category_name.data,
                  utm_form.url_filtering_name.data,
                  utm_form.confilter_name.data,
                  utm_form.confilter_name.data,
                  utm_form.old_policy_name.data,
                  utm_form.old_dst_zone.data,
                  utm_form.old_src_zone.data,

        )
        # tmp.name = utm_name
        print("utm name is ",utm_form.name.data)
        print("utm_form.old_src_zone.data is ",utm_form.old_src_zone.data)
        # tmp.spam_black_list_pattern_name = utm_spam_black_list_pattern_name
        # tmp.sbl_profile_name = utm_sbl_profile_name
        # tmp.url_black_list_pattern_name = utm_url_black_list_pattern_name
        # tmp.url_black_list_category_name = utm_url_black_list_category_name
        # tmp.url_filtering_name = utm_url_filtering_name
        # tmp.confilter_name = utm_confilter_name
        # tmp.new_policy_name = utm_new_policy_name
        # tmp.old_policy_name = utm_old_policy_name.strip(',')[0]
        # tmp.old_dst_zone = utm_old_policy_name.strip(',')[1]
        # tmp.old_src_zone = utm_old_policy_name.strip(',')[2]
        db_session.add(tmp)
        db_session.commit()
        flash('template saved successfully')
        return redirect(url_for('templates'))

    tmp_type = request.args['type']
    print(tmp_type)
    if tmp_type == 'vpn':
        return render_template(
            "add_template.html", is_vpn=True, vpn_form=vpn_form)
    if tmp_type == 'utm':
        return render_template(
            "add_template.html", is_utm=True, utm_form=utm_form)
    if tmp_type == 'idp':
        return render_template(
            "add_template.html", is_vpn=True, vpn_form=vpn_form)


@app.route("/template/edit/VPN/<tid>", methods=['GET', 'POST'])
@login_required
def edit_VPN_template(tid):
    tmp = db_session.query(VPN).filter_by(tid=tid).first()
    vpn_form = VPNForm()
    if request.method == 'GET':
        vpn_form.name.data = tmp.name
        vpn_form.LTE_cloudGW.data = tmp.LTE_cloudGW
        vpn_form.LTE_external_interface.data = tmp.LTE_external_interface
        vpn_form.LTE_local_identity.data = tmp.LTE_local_identity
        vpn_form.LTE_remote_identity.data = tmp.LTE_remote_identity
        vpn_form.cloud_external_interface.data = tmp.cloud_external_interface
        vpn_form.cloud_local_address.data = tmp.cloud_local_address
        vpn_form.phase1_dh_group.data = tmp.phase1_dh_group
        vpn_form.phase1_authentication_algorithm.data = tmp.phase1_authentication_algorithm
        vpn_form.phase1_encryption_algorithm.data = tmp.phase1_encryption_algorithm
        vpn_form.phase1_pre_shared_key.data = tmp.phase1_pre_shared_key
        vpn_form.phase1_dead_peer_detection_nterval.data = tmp.phase1_dead_peer_detection_nterval
        vpn_form.phase1_dead_peer_detection_threshold.data = tmp.phase1_dead_peer_detection_threshold
        vpn_form.phase2_authentication_algorithm.data = tmp.phase2_authentication_algorithm
        vpn_form.phase2_encryption_algorithm.data = tmp.phase2_encryption_algorithm
        vpn_form.phase2_perfect_forward_secrecy_keys.data = tmp.phase2_perfect_forward_secrecy_keys

    if vpn_form.validate_on_submit():
        tmp2 = db_session.query(VPN).filter(VPN.tid == tid).update({
            'name' : vpn_form.name.data,
            'LTE_cloudGW' : vpn_form.LTE_cloudGW.data,
            'LTE_external_interface' : vpn_form.LTE_external_interface.data,
            'LTE_local_identity' : vpn_form.LTE_local_identity.data,
            'LTE_remote_identity' : vpn_form.LTE_remote_identity.data,
            'cloud_external_interface' : vpn_form.cloud_external_interface.data,
            'cloud_local_address' : vpn_form.cloud_local_address.data,
            'phase1_dh_group' : vpn_form.phase1_dh_group.data,
            'phase1_authentication_algorithm' : vpn_form.phase1_authentication_algorithm.data,
            'phase1_encryption_algorithm' : vpn_form.phase1_encryption_algorithm.data,
            'phase1_pre_shared_key' : vpn_form.phase1_pre_shared_key.data,
            'phase1_dead_peer_detection_nterval' : vpn_form.phase1_dead_peer_detection_nterval.data,
            'phase1_dead_peer_detection_threshold' : vpn_form.phase1_dead_peer_detection_threshold.data,
            'phase2_authentication_algorithm' : vpn_form.phase2_authentication_algorithm.data,
            'phase2_encryption_algorithm' : vpn_form.phase2_encryption_algorithm.data,
            'phase2_perfect_forward_secrecy_keys' : vpn_form.phase2_perfect_forward_secrecy_keys.data,
        })
        db_session.commit()
        print(vpn_form.name.data)
        flash('template saved successfully')
        return redirect(url_for('templates'))

    # if probe_form.validate_on_submit():
    #   return jsonify(errmsg="success")
    return render_template("edit_template.html", vpn_form=vpn_form, tid=tid, is_vpn=True)


@app.route("/template/edit/UTM/<tid>", methods=['GET', 'POST'])
@login_required
def edit_UTM_template(tid):
    tmp = db_session.query(UTM).filter_by(tid=tid).first()
    utm_form = UTMForm()
    if request.method == 'GET':
        utm_form.content_filtering.data = tmp.content_filtering
        utm_form.anti_virus.data = tmp.anti_virus
        utm_form.anti_spam.data = tmp.anti_spam
        utm_form.antispam_default.data = tmp.antispam_default
        utm_form.antispam_custom.data = tmp.antispam_custom
        utm_form.url_filtering.data = tmp.url_filtering
        utm_form.spam_black_list_value.data = tmp.spam_black_list_value
        utm_form.spam_action.data = tmp.spam_action
        utm_form.url_black_list_value.data = tmp.url_black_list_value
        utm_form.url_black_list_action.data = tmp.url_black_list_action
        utm_form.block_contype.data = tmp.block_contype
        utm_form.old_status.data = tmp.old_status
        utm_form.old_policy_name.data = tmp.old_policy_name
        utm_form.old_src_zone.data = tmp.old_src_zone
        utm_form.old_dst_zone.data = tmp.old_dst_zone
        utm_form.src_zone.data = tmp.src_zone
        utm_form.dst_zone.data = tmp.dst_zone
        utm_form.src_address.data = tmp.src_address
        utm_form.dst_address.data = tmp.dst_address
        utm_form.new_policy_name.data = tmp.new_policy_name

    if utm_form.validate_on_submit():
        # db_session.delete(tmp)
        tmp2 = db_session.query(UTM).filter(UTM.tid == tid).update({
            'anti_virus':utm_form.anti_virus.data,
            'anti_spam':utm_form.anti_spam.data,
            'url_filtering':utm_form.url_filtering.data,
            'content_filtering':utm_form.content_filtering.data,
            'antispam_default':utm_form.antispam_default.data,
            'antispam_custom':utm_form.antispam_custom.data,
            'spam_black_list_value':utm_form.spam_black_list_value.data,
            'spam_action':utm_form.spam_action.data,
            'url_black_list_value':utm_form.url_black_list_value.data,
            'url_black_list_action':utm_form.url_black_list_action.data,
            'block_contype':utm_form.block_contype.data,
            'old_status':utm_form.old_status.data,
            'old_policy_name':utm_form.old_policy_name.data.strip().split(':')[0],
            'old_src_zone':utm_form.old_policy_name.data.strip().split(':')[2],
            'old_dst_zone':utm_form.old_policy_name.data.strip().split(':')[1],
            'src_zone':utm_form.src_zone.data,
            'dst_zone':utm_form.dst_zone.data,
            'src_address':utm_form.src_address.data,
            'dst_address':utm_form.dst_address.data,
        })
        db_session.commit()
        flash('template saved successfully')
        return redirect(url_for('templates'))

    return render_template("edit_template.html", utm_form=utm_form, tid=tid, is_utm=True)


@app.route("/deployments")
@login_required
def deployments():
    return ""


matchers = [('glob', 'Glob'), ('pcre', 'Perl regular expression'), ('list',
                                                                    'List'),
            ('grain', 'Grain'), ('grain_pcre', 'Grain perl regex'), ('pillar',
                                                                     'Pillar'),
            ('nodegroup', 'Nodegroup'), ('range', 'Range'), ('compound',
                                                             'Compound')]
probe_type = [('0', '0'), ('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'),
              ('5', '5'), ('6', '6')]

hardware_time = [('True', 'True'), ('False', 'False')]
LTE_cloudGW = [('112.35.30.65', '112.35.30.65'),
               ('112.35.30.67', '112.35.30.67'), ('112.35.30.69',
                                                  '112.35.30.69')]
LTE_external_interface = [('ge-0/0/0', 'ge-0/0/0'), ('ge-0/0/1', 'ge-0/0/1')]
LTE_internal_interface = [('ge-0/0/2', 'ge-0/0/2'), ('ge-0/0/1', 'ge-0/0/1')]
cloud_internal_interface = [('ge-0/0/1', 'ge-0/0/1'), ('ge-0/0/2', 'ge-0/0/2')]
dh_group = [('group1', 'group1'), ('group2', 'group2'), ('group5', 'group5')]

phase1_authentication_algorithm = [('md5', 'md5'), ('sha-256', 'sha-256'),
                                   ('sha1', 'sha1')]

phase1_encryption_algorithm = [('3des-cbc', '3des-cbc'),
                               ('aes-128-cbc', 'aes-128-cbc'), ('aes-192-cbc',
                                                                'aes-192-cbc'),
                               ('aes-256-cbc', 'aes-256-cbc'), ('des-cbc',
                                                                'des-cbc')]

phase1_pre_shared_key = [('ascii-text $ABC123', 'ascii-text $ABC123')]

ipsec_protocol = [('ah', 'ah'), ('esp', 'esp')]
phase2_authentication_algorithm = [('hmac-md5-96', 'hmac-md5-96'),
                                   ('hmac-sha1-96', 'hmac-sha1-96')]
phase2_encryption_algorithm = [('3des-cbc', '3des-cbc'),
                               ('aes-128-cbc', 'aes-128-cbc'), ('aes-192-cbc',
                                                                'aes-192-cbc'),
                               ('aes-256-cbc', 'aes-256-cbc'), ('des-cbc',
                                                                'des-cbc')]
phase2_perfect_forward_secrecy_keys = [('group1', 'group1'),
                                       ('group2', 'group2'), ('group5',
                                                              'group5')]

#utm
anti_virus = [('enable', 'enable'), ('noenable', 'noenable')]
content_filtering = [('enable', 'enable'), ('noenable', 'noenable')]
# antivirus_http = [('enable', 'enable'), ('noenable', 'noenable')]
# antivirus_smtp = [('enable', 'enable'), ('noenable', 'noenable')]
# antivirus_ftp = [('enable', 'enable'), ('noenable', 'noenable')]
anti_spam = [('enable', 'enable'), ('noenable', 'noenable')]
antispam_default = [('enable', 'enable'), ('noenable', 'noenable')]
antispam_custom = [('enable', 'enable'), ('noenable', 'noenable')]
url_filtering = [('enable', 'enable'), ('noenable', 'noenable')]
spam_action = [('block', 'block'), ('tag-header', 'tag-header'),
               ('tag-subject', 'tag-subject')]
url_black_list_action = [('block', 'block'), ('peimit', 'permit'),
                         ('log and permit', 'log and permit')]
block_contype = [('java-applet', 'java-applet'), ('exe', 'exe'),
                 ('http-cookie', 'http-cookie'), ('zip', 'zip')]
# url_white_list_action = [('block', 'block'), ('peimit', 'permit'),
#  ('log and permit', 'log and permit')]
# fallback_setting_default = [('block', 'block'), ('log and permit',
#                                                  'log and permit')]
# fallback_setting_server_connectivity = [('block', 'block'), ('log and permit',
#                                                              'log and permit')]
# fallback_setting_timeout = [('block', 'block'), ('log and permit',
#                                                  'log and permit')]
# fallback_setting_too_many_requests = [('block', 'block'), ('log and permit',
#    'log and permit')]
old_status = [('enable', 'enable'), ('noenable', 'noenable')]
# old_src_zone = [('trust', 'trust'), ('untrust', 'untrust')]
# old_dst_zone = [('trust', 'trust'), ('untrust', 'untrust')]
old_policy_name = [('Client-Outbound-2','Client-Outbound-2,untrust,trust'),('Client-Outbound-1','Client-Outbound-1,untrust,trust'),('Client-Outbound-3','Client-Outbound-3,untrust,trust')]
src_zone = [('trust', 'trust'), ('untrust', 'untrust')]
dst_zone = [('trust', 'trust'), ('untrust', 'untrust')]
#idp
rule_src_zone = [('trust', 'trust'), ('untrust', 'untrust')]
rule_dst_zone = [('trust', 'trust'), ('untrust', 'untrust')]
idprule_action = [('no-action','no-action'),
    ('ignore-connection','ignore-connection'),('drop-packet','drop-packet'),
    ('drop-connection','drop-connection'),('close-client','close-client'),
    ('close-server','close-server'),('close-client-and-server','close-client-and-server')]
idprule_sev = [('critical','critical'),('info','info'),('major','major'),('minor','minor'),('warning','warning')]
predefine_idp = [('enable', 'enable'), ('noenable', 'noenable')]
custom_idp = [('enable', 'enable'), ('noenable', 'noenable')]
cus_attack_serverity = [('critical','critical'),('info','info'),('major','major'),('minor','minor'),('warning','warning')]
cus_attack_action = [('close','close'),('close-client','close-client'),('close-server','close-server'),('drop','drop'),('drop-packet','drop-packet'),('ignore','ignore'),('none','none')]
cus_attack_direction = [('any','any'),('client-to-server','client-to-server'),('server-to-client','server-to-client')]

class RunForm(Form):
    expr_form = SelectField('matcher', choices=matchers)
    tgt = StringField('target', validators=[DataRequired()])
    fun = StringField('function', validators=[DataRequired()])
    arg = StringField('arg', validators=None)


class ProbeForm(Form):
    owner = StringField('owner', validators=[DataRequired()])  #32字符
    test_name = StringField('test-name', validators=[DataRequired])  #32字符
    probe_type = SelectField('probe-type', choices=probe_type)  #0-6
    data_size = StringField('data-size', validators=[DataRequired])  #0-65507
    data_fill = StringField(
        'datafill', validators=[DataRequired])  #1-800h 16进制 和data-size要都有或都没有
    destination_port = StringField(
        'destination-port', validators=[DataRequired])  #7 或 49160-65535
    dscp_code_point = StringField(
        'dscp-code-point', validators=[DataRequired])  #6bits
    hardware_time = SelectField(
        'hardware-timestamp', choices=hardware_time)  #yes or no
    history_size = StringField(
        'history-size', validators=[DataRequired])  #0-255
    moving_average_size = StringField(
        'moving-average-size', validators=[DataRequired])  #0-255
    probe_count = StringField('probe-count', validators=[DataRequired])  #1-15
    probe_interval = StringField(
        'probe-interval', validators=[DataRequired])  #1-255
    source_address = StringField(
        'source_address', validators=[DataRequired])  #接口地址
    target = StringField('target', validators=[DataRequired])  #http必须要有，或者用ip
    test_interval = StringField(
        'test-interval', validators=[DataRequired])  #0-86400


class VPNForm(Form):
    name = StringField('name', validators=[DataRequired()])  #必填
    LTE_cloudGW = SelectField(
        'LTE-cloudGW', choices=LTE_cloudGW, default='112.35.30.67')
    LTE_external_interface = SelectField(
        'LTE-external-interface',
        choices=LTE_external_interface,
        default='ge-0/0/0')
    # LTE_internal_interface = SelectField('LTE-internal-interface',choices=LTE_internal_interface)
    LTE_local_identity = StringField(
        'LTE-local-identity', validators=[DataRequired()])
    LTE_remote_identity = StringField(
        'LTE-remote-identity', validators=[DataRequired()], default='CGW-2')
    cloud_external_interface = StringField(
        'cloud-external-interface',
        validators=[DataRequired()],
        default='ge-0/0/0')
    # cloud_internal_interface = SelectField('cloud-internal-interface', choices=cloud_internal_interface)
    cloud_local_address = StringField(
        'cloud-local-address',
        validators=[DataRequired()],
        default='10.112.44.113')
    # network_segment = StringField('network-segment', validators=[DataRequired()])#必填
    phase1_dh_group = SelectField(
        'phase1-dh-group', choices=dh_group, default='group2')
    phase1_authentication_algorithm = SelectField(
        'phase1-authentication-algorithm',
        choices=phase1_authentication_algorithm,
        default='sha1')
    phase1_encryption_algorithm = SelectField(
        'phase1-encryption-algorithm',
        choices=phase1_encryption_algorithm,
        default='aes-128-cbc')
    phase1_pre_shared_key = SelectField(
        'phase1-pre-shared-key',
        choices=phase1_pre_shared_key,
        default='ascii-text $ABC123')
    # ipsec_protocol = SelectField('ipsec-protocol',choices=ipsec_protocol)
    phase1_dead_peer_detection_nterval = StringField(
        'phase1_dead_peer_detection_nterval',
        validators=[DataRequired()],
        default='10')
    phase1_dead_peer_detection_threshold = StringField(
        'phase1_dead_peer_detection_threshold',
        validators=[DataRequired()],
        default='3')
    phase2_authentication_algorithm = SelectField(
        'phase2_authentication_algorithm',
        choices=phase2_authentication_algorithm)
    phase2_encryption_algorithm = SelectField(
        'phase2_encryption_algorithm', choices=phase2_encryption_algorithm)
    phase2_perfect_forward_secrecy_keys = SelectField(
        'phase2_perfect_forward_secrecy_keys',
        choices=phase2_perfect_forward_secrecy_keys,
        default='group2')


def validate_network_segment(form, field):
    try:
        startIpSegment = field.data.strip().split('-')[0]  # 192.168.1.1/24
        startIp = startIpSegment.split('/')[0]  # 192.168.1.1
        startSubnetMask = startIpSegment.split('/')[1]  # 24

        endIpSegment = field.data.strip().split('-')[1]  # 192.168.1.10/24
        endIp = endIpSegment.split('/')[0]  # 192.168.1.10
        endSubnetMask = endIpSegment.split('/')[1]  # 24
    except:
        raise ValidationError(
            "please input correct format like '10.0.0.1/24-10.1.0.0/24'")

def validate_by_antispam_custom(form, field):
  if form.antispam_custom.data == 'enable':
    if field.data == '':
      raise ValidationError("选择 antispam_custom 时，该选项为必填字段")

def validate_by_url_filtering(form, field):
  if form.url_filtering.data == 'enable':
    if field.data == '':
      raise ValidationError("选择 url_filtering 时，该选项为必填字段")

def validate_by_content_filtering(form, field):
  if form.content_filtering.data == 'enable':
    if field.data == '':
      raise ValidationError("选择 content_filtering 时，该选项为必填字段")

def validate_by_old_status(form, field):
  if form.old_status.data == 'enable':
    if field.data == '':
      raise ValidationError("选择 old_status 时，该选项为必填字段")

def validate_new_status(form, field):
  if form.old_status.data == 'noenable':
    if field.data == '':
      raise ValidationError("选择新建 policy 时，该选项为必填字段")


class UTMForm(Form):
    name = StringField('name', validators=[DataRequired()])  #必填
    anti_virus = SelectField(
        'anti_virus', choices=anti_virus, default='enable')
    anti_spam = SelectField(
        'anti_spam', choices=anti_spam, default='anti_spam')
    antispam_default = SelectField(
        'antispam_default', choices=antispam_default, default='noenable')
    antispam_custom = SelectField(
        'antispam_custom', choices=antispam_custom, default='enable')
    spam_black_list_value = StringField(
        'spam_black_list_value', validators=[validate_by_antispam_custom])
    spam_black_list_pattern_name = StringField(
        'spam_black_list_pattern_name', validators=[validate_by_antispam_custom])
    spam_action = SelectField(
        'spam_action', choices=spam_action, default='block')
    sbl_profile_name = StringField(
        'sbl_profile_name')

    url_filtering = SelectField(
        'url_filtering', choices=url_filtering, default='enable')
    url_black_list_value = StringField(
        'url_black_list_value', validators=[validate_by_url_filtering])
    url_black_list_pattern_name = StringField(
        'url_black_list_pattern_name', validators=[validate_by_url_filtering])
    url_black_list_category_name = StringField(
        'url_black_list_category_name', validators=[validate_by_url_filtering])
    url_black_list_action = SelectField(
        'url_black_list_action',
        choices=url_black_list_action,
        default='block')
    url_filtering_name = StringField(
        'url_filtering_name')

    content_filtering = SelectField(
        'content_filtering', choices=content_filtering, default='enable')
    confilter_name = StringField('confilter_name')
    block_contype = SelectMultipleField('block_contype', choices=block_contype, validators=[validate_by_content_filtering])

    old_status = SelectField(
        'old_status', choices=old_status, default='enable')
    old_policy_name = StringField(
        'old_policy_name', validators=[validate_by_old_status])
    # old_src_zone = StringField('old_src_zone', validators=[DataRequired()])
    # old_dst_zone = StringField('old_dst_zone', validators=[DataRequired()])

    src_zone = SelectField('src_zone', choices=dst_zone, default='trust')
    dst_zone = SelectField('dst_zone', choices=dst_zone, default='untrust')
    src_address = StringField(
        'src_address', validators=[validate_new_status], default='any')
    dst_address = StringField(
        'dst_address', validators=[validate_new_status], default='any')
    new_policy_name = StringField(
        'new_policy_name', validators=[validate_by_old_status])
class IDPForm(Form):
    name = StringField('name', validators=[DataRequired()])
    idp_rule_name = StringField('idp_rule_name')
    rule_src_zone = SelectField('rule_src_zone',choices=rule_src_zone,default = 'trust')
    rule_dst_zone = SelectField('rule_src_zone',choices=rule_src_zone,default = 'trust')
    idprule_action = SelectField('idprule_action',choices=idprule_action)
    idprule_sev = SelectField('idprule_sev',choices=idprule_sev)
    predefine_idp = SelectField('predefine_idp',choices=predefine_idp,default = 'enable')
    custom_idp = SelectField('custom_idp',choices=custom_idp,default = 'untrust')
    cus_attack_name = StringField('cus_attack_name')
    cus_attack_serverity = SelectField('cus_attack_serverity',choices=cus_attack_serverity)
    cus_attack_action = SelectField('cus_attack_action',choices=cus_attack_action)
    cus_attack_direction = SelectField('cus_attack_direction',choices=cus_attack_direction)

    old_status = SelectField(
        'old_status', choices=old_status, default='enable')
    old_policy_name = SelectField(
        'old_policy_name', choices=old_policy_name)
    # old_src_zone = StringField('old_src_zone', validators=[DataRequired()])
    # old_dst_zone = StringField('old_dst_zone', validators=[DataRequired()])

    src_zone = SelectField('src_zone', choices=dst_zone, default='trust')
    dst_zone = SelectField('dst_zone', choices=dst_zone, default='untrust')
    src_address = StringField(
        'src_address', validators=[DataRequired()], default='any')
    dst_address = StringField(
        'dst_address', validators=[DataRequired()], default='any')
    new_policy_name = StringField(
        'new_policy_name')

class NewTemplateForm(RunForm):
    name = StringField('name', validators=[DataRequired()])
    description = TextAreaField('description', validators=[DataRequired()])


@app.route('/run', methods=["GET", "POST"])
@login_required
def run():
    form = RunForm()
    if form.validate_on_submit():

        args = get_filtered_post_arguments(('csrf_token', 'tgt', 'fun', 'args',
                                            'expr_form', 'arg'))
        #print args,"==================================================>"
        jid = client.run(
            form.fun.data.strip(),
            client="local_async",
            tgt=form.tgt.data.strip(),
            arg=form.arg.data.strip(),
            expr_form=form.expr_form.data.strip(),
            args=Call(**args))['jid']
        return redirect(url_for('job_result', jid=jid))
    return render_template("run.html", form=form)


@app.route("/job/redo/<jid>")
@login_required
def redo_job(jid):
    minion = request.args.get('minion', None)
    renderer = request.args.get('renderer', 'raw')
    job = client.job(jid)

    if not job:
        return "Unknown jid", 404

    try:
        new_jid = client.run(
            job['info']['Function'],
            client="local_async",
            tgt=job['info']['Target'],
            expr_form=job['info']['Target-type'],
            args=job['info']['Arguments'])['jid']
    except JobNotStarted:
        msg = "Couldn't redo the job, check salt api log for more details"
        flash(msg, 'error')
        return redirect(
            url_for(
                'job_result', minion=minion, jid=jid, renderer='highstate'))

    return redirect(
        url_for(
            'job_result', minion=minion, jid=new_jid, renderer='highstate'))


@app.route('/doc_search', methods=["POST", "OPTIONS"])
@login_required
def doc_search():
    content = request.json

    arg_specs = client.run(
        'sys.argspec',
        client='local',
        tgt=content['tgt'].strip(),
        expr_form=content['expr_form'],
        args=Call(content['fun'].strip()))

    if not arg_specs:
        return jsonify({'error': 'No matching minions found'}), 400

    # Take only first result
    arg_specs = list(arg_specs.values())[0]

    module_function_names = list(arg_specs.keys())

    docs = client.run(
        'sys.doc',
        client='local',
        tgt=content['tgt'].strip(),
        expr_form=content['expr_form'],
        args=Call(*module_function_names))

    # Take only first result
    docs = list(docs.values())[0]

    result = {}

    for module_function_name in module_function_names:
        result[module_function_name] = {
            'spec': parse_argspec(arg_specs[module_function_name]),
            'doc': docs[module_function_name]
        }

    return jsonify(result)


@app.route('/minions_keys')
@login_required
def minions_keys():
    content = request.json
    minions_keys = client.run('key.list_all', client='wheel')['data']['return']
    return render_template("minions_keys.html", keys=minions_keys)


@app.route('/keys/delete/<key>')
@login_required
def delete_key(key):
    content = request.json
    minions_keys = client.run(
        'key.delete', client="wheel", match=key)['data']['return']
    return redirect(url_for('minions_keys'))


@app.route('/keys/reject/<key>')
@login_required
def reject_key(key):
    content = request.json
    client.run('key.reject', client="wheel", arg=key)['data']['return']
    return redirect(url_for('minios_keys'))


@app.route('/keys/accept/<key>')
@login_required
def accept_key(key):
    content = request.json
    client.run('key.accept', client="wheel", match=key)['data']['return']
    return redirect(url_for('minions_keys'))


@app.route('/minion/<minion>')
@login_required
def minion_details(minion):
    minion_details = client.minion_details(minion)
    if not minion_details['return'][0]:
        minion_details['status'] = 'down'
    else:
        minion_details['status'] = 'up'
    minion_details['name'] = minion
    return render_template(
        "minion_details.html", minion_details=minion_details)


@app.route('/debug/')
@login_required
def debug():
    minions = client.minions()
    minions_status = client.minions_status()

    for minion in minions_status['up']:
        minions.setdefault(minion, {})['state'] = 'up'

    for minion in minions_status['down']:
        minions.setdefault(minion, {})['state'] = 'down'

    return render_template('debug.html', minions=minions)


@app.route('/debug/<minion>')
@login_required
def debug_minion(minion):

    pillar_data = client.run(
        "pillar.items", client="local", tgt=minion)[minion]
    # Make a PR for that
    #pillar_top = client.run("pillar.show_top", client="runner", minion=minion)
    state_top = client.run(
        "state.show_top", client="local", tgt=minion)[minion]
    lowstate = client.run(
        "state.show_lowstate", client="local", tgt=minion)[minion]
    grains = client.run("grains.items", client="local", tgt=minion)[minion]

    return render_template(
        'debug_minion.html',
        minion=minion,
        pillar_data=pillar_data,
        state_top=state_top,
        lowstate=lowstate,
        grains=grains)


@app.route('/wip')
@login_required
def wip():
    return render_template("wip.html")


@app.template_filter("aggregate_len_sort")
def aggregate_len_sort(unsorted_dict):
    return sorted(unsorted_dict.items(), key=lambda x: len(x[1]), reverse=True)


@app.template_filter("format_arguments")
def format_argument(arguments):
    return " ".join(format_arguments(arguments))


@app.template_filter("dict_sort_value_subkey")
def format_argument(arguments, sort_key):
    return sorted(list(arguments.items()), key=lambda item: item[1][sort_key])


@app.template_filter("is_string")
def format_argument(instance):
    return isinstance(instance, string_types)


@app.route('/topo/traffic_path')
@login_required
def traffic_path():
    return render_template('traffic_path.html', isTopo=True)


@app.route('/topo/control_path')
@login_required
def control_path():
    return render_template('control_path.html', isTopo=True)


from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup, SoupStrainer

import datetime, subprocess, logging

log = logging.getLogger('apscheduler.executors.default')
log.setLevel(logging.INFO)  # DEBUG

fmt = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
h = logging.StreamHandler()
h.setFormatter(fmt)
log.addHandler(h)

ike_data_list = []
ike_remote_address = []


def run_script():
    content = subprocess.check_output("python getVPNinfo.py", shell=True)
    # content = open('mock.txt', 'r')
    data = BeautifulSoup(content, "html.parser")

    ike_data = data.find_all('rpc-reply')[0]
    ipsec_data = data.find_all('rpc-reply')[1]

    node_data = ike_data.find_all('ike-security-associations')

    global ike_data_list
    global ike_remote_address
    for node in node_data:
        single_ike_data = {
            'remote_address': node.find('ike-sa-remote-address').string,
            'index': node.find('ike-sa-index').string,
            'state': node.find('ike-sa-state').string,
            'initiator_cookie': node.find('ike-sa-initiator-cookie').string,
            'responder_cookie': node.find('ike-sa-responder-cookie').string,
            'exchange_type': node.find('ike-sa-exchange-type').string,
        }
        if single_ike_data['remote_address'] not in ike_remote_address:
            ike_remote_address.append(single_ike_data['remote_address'])
            ike_data_list.append(single_ike_data)


@app.route('/vpn_info')
def getVpnInfo():
    return jsonify(data=ike_data_list, err_msg="success")


def timer_mission():
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_script,
        'interval',
        start_date=datetime.datetime.now() + datetime.timedelta(seconds=1),
        minutes=15)
    scheduler.start()


@app.route("/templates/VPN/new", methods=['POST'])
@login_required
def add_VPN_template():

    VPN_name = request.json['name']
    LTE_cloudGW = request.json['LTE_cloudGW']
    LTE_external_interface = request.json['LTE_external_interface']
    LTE_local_identity = request.json['LTE_local_identity']
    LTE_remote_identity = request.json['LTE_remote_identity']
    cloud_external_interface = request.json['cloud_external_interface']
    cloud_local_address = request.json['cloud_local_address']
    # network_segment = request.json['network_segment']
    phase1_dh_group = request.json['phase1_dh_group']
    phase1_authentication_algorithm = request.json[
        'phase1_authentication_algorithm']
    phase1_encryption_algorithm = request.json['phase1_encryption_algorithm']
    phase1_pre_shared_key = request.json['phase1_pre_shared_key']
    phase1_dead_peer_detection_nterval = request.json[
        'phase1_dead_peer_detection_nterval']
    phase1_dead_peer_detection_threshold = request.json[
        'phase1_dead_peer_detection_threshold']
    phase2_authentication_algorithm = request.json[
        'phase2_authentication_algorithm']
    phase2_encryption_algorithm = request.json['phase2_encryption_algorithm']
    phase2_perfect_forward_secrecy_keys = request.json[
        'phase2_perfect_forward_secrecy_keys']

    tmp = VPN(vpn_form.name.data, vpn_form.LTE_cloudGW.data,
              vpn_form.LTE_external_interface.data,
              vpn_form.LTE_local_identity.data,
              vpn_form.LTE_remote_identity.data,
              vpn_form.cloud_external_interface.data,
              vpn_form.cloud_local_address.data, vpn_form.phase1_dh_group.data,
              vpn_form.phase1_authentication_algorithm.data,
              vpn_form.phase1_encryption_algorithm.data,
              vpn_form.phase1_pre_shared_key.data,
              vpn_form.phase1_dead_peer_detection_nterval.data,
              vpn_form.phase1_dead_peer_detection_threshold.data,
              vpn_form.phase2_authentication_algorithm.data,
              vpn_form.phase2_encryption_algorithm.data,
              vpn_form.phase2_perfect_forward_secrecy_keys)
    print(tmp)
    test = db_session.query(VPN).filter_by(name=VPN_name).first()
    if test.name != None:
        return jsonify(errmsg="primary key conflict", data="1")

    db_session.add(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')


@app.route('/templates/VPN/delete', methods=['POST'])
@login_required
def del_VPN_template():
    # print(request.json)
    VPN_name = request.json['name']
    # network_segment = request.json['network_segment']

    tmp = db_session.query(VPN).filter_by(name=VPN_name).first()
    if tmp.name == None:
        return jsonify(errmsg="No such template", data='2')

    db_session.delete(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')


@app.route('/templates/UTM/delete', methods=['POST'])
@login_required
def del_UTM_tempalte():
    UTM_name = request.json['name']
    tmp = db_session.query(UTM).filter_by(name=UTM_name).first()
    if tmp.name == None:
        return jsonify(errmsg="No such tempalte", data='2')
    db_session.delete(tmp)
    db_session.commit()
    return jsonify(errmsg="success", data='0')

@app.route('/templates/IDP/delete', methods=['POST'])
@login_required
def del_IDP_tempalte():
    IDP_name = request.json['name']
    tmp = db_session.query(IDP).filter_by(name=IDP_name).first()
    if tmp.name == None:
        return jsonify(errmsg="No such tempalte", data='2')
    db_session.delete(tmp)
    db_session.commit()
    return jsonify(errmsg="success", data='0')


@app.route('/templates/VPN/modify', methods=['POST'])
@login_required
def modify_VPN_template():

    VPN_name = request.json['name']
    LTE_cloudGW = request.json['LTE_cloudGW']
    LTE_external_interface = request.json['LTE_external_interface']
    LTE_local_identity = request.json['LTE_local_identity']
    LTE_remote_identity = request.json['LTE_remote_identity']
    cloud_external_interface = request.json['cloud_external_interface']
    cloud_local_address = request.json['cloud_local_address']
    # network_segment = request.json['network_segment']
    phase1_dh_group = request.json['phase1_dh_group']
    phase1_authentication_algorithm = request.json[
        'phase1_authentication_algorithm']
    phase1_encryption_algorithm = request.json['phase1_encryption_algorithm']
    phase1_pre_shared_key = request.json['phase1_pre_shared_key']
    phase1_dead_peer_detection_nterval = request.json[
        'phase1_dead_peer_detection_nterval']
    phase1_dead_peer_detection_threshold = request.json[
        'phase1_dead_peer_detection_threshold']
    phase2_authentication_algorithm = request.json[
        'phase2_authentication_algorithm']
    phase2_encryption_algorithm = request.json['phase2_encryption_algorithm']
    phase2_perfect_forward_secrecy_keys = request.json[
        'phase2_perfect_forward_secrecy_keys']

    tmp = db_session.query(VPN).filter_by(name=VPN_name).first()

    db_session.delete(tmp)
    db_session.commit()

    tmp = VPN(
        vpn_form.name.data, vpn_form.LTE_cloudGW.data,
        vpn_form.LTE_external_interface.data, vpn_form.LTE_local_identity.data,
        vpn_form.LTE_local_identity.data, vpn_form.LTE_remote_identity.data,
        vpn_form.cloud_external_interface.data,
        vpn_form.cloud_local_address.data, vpn_form.phase1_dh_group.data,
        vpn_form.phase1_authentication_algorithm.data,
        vpn_form.phase1_encryption_algorithm.data,
        vpn_form.phase1_pre_shared_key.data,
        vpn_form.phase1_dead_peer_detection_nterval.data,
        vpn_form.phase1_dead_peer_detection_threshold.data,
        vpn_form.phase2_authentication_algorithm.data,
        vpn_form.phase2_encryption_algorithm.data,
        vpn_form.phase2_perfect_forward_secrecy_keys)

    db_session.add(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')


@app.route('/templates/VPN/query', methods=['POST'])
@login_required
def query_VPN_template():

    VPN_name = request.json['name']

    tmp = db_session.query(VPN).filter_by(name=VPN_name).first()

    # print (tmp)

    return jsonify(errmsg="success", data=json.dumps(tmp, default=VPN2dict))


@app.route('/templates/UTM/query', methods=['POST'])
@login_required
def query_UTM_tempalte():
    UTM_name = request.json['name']
    tmp = db_session.query(UTM).filter_by(name=UTM_name).first()
    return jsonify(errmsg="success", data=json.dumps(tmp, default=UTM2dict))

@app.route('/templates/IDP/query', methods=['POST'])
@login_required
def query_IDP_tempalte():
    UTM_name = request.json['name']
    tmp = db_session.query(IDP).filter_by(name=IDP_name).first()
    return jsonify(errmsg="success", data=json.dumps(tmp, default=UTM2dict))


@app.route('/templates/UTM/all', methods=['GET'])
@login_required
def query_all_UTM_tempalte():
    tmp = db_session.query(UTM).all()
    return jsonify(errmsg="success", data=json.dumps(tmp, default=UTM2dict))

@app.route('/templates/IDP/all', methods=['GET'])
@login_required
def query_all_IDP_tempalte():
    tmp = db_session.query(IDP).all()
    return jsonify(errmsg="success", data=json.dumps(tmp, default=UTM2dict))


@app.route('/templates/VPN/all', methods=['GET'])
@login_required
def query_all_VPN_template():

    # VPN_name = request.json['name']

    tmp = db_session.query(VPN).all()

    return jsonify(errmsg="success", data=json.dumps(tmp, default=VPN2dict))


def UTM2dict(utms):
    result = []
    for utm in utms:
        single = {
            "name": utm.name,
            "content_filtering": utm.content_filtering,
            "anti_virus": utm.anti_virus,
            "anti_spam": utm.anti_spam,
            "antispam_default": utm.antispam_default,
            "antispam_custom": utm.antispam_custom,
            "url_filtering": utm.url_filtering,
            "spam_black_list_value": utm.spam_black_list_value,
            "spam_black_list_pattern_name": utm.spam_black_list_pattern_name,
            "spam_action": utm.spam_action,
            "sbl_profile_name": utm.sbl_profile_name,
            "url_black_list_value": utm.url_black_list_value,
            "url_black_list_pattern_name": utm.url_black_list_pattern_name,
            "url_black_list_category_name": utm.url_black_list_category_name,
            "url_black_list_action": utm.url_black_list_action,
            "url_filtering_name": utm.url_filtering_name,
            "confilter_name": utm.confilter_name,
            "block_contype": utm.block_contype,
            "old_status": utm.old_status,
            "old_policy_name": utm.old_policy_name,
            "old_src_zone": utm.old_src_zone,
            "old_dst_zone": utm.old_dst_zone,
            "src_zone": utm.src_zone,
            "dst_zone": utm.dst_zone,
            "src_address": utm.src_address,
            "dst_address": utm.dst_address,
            "new_policy_name": utm.new_policy_name
        }
        result.append(single)
    return result


def VPN2dict(vpns):
    result = []
    for vpn in vpns:
        single = {
            "tid":
            vpn.tid,
            "name":
            vpn.name,
            "LTE_cloudGW":
            vpn.LTE_cloudGW,
            "LTE_external_interface":
            vpn.LTE_external_interface,
            "LTE_local_identity":
            vpn.LTE_local_identity,
            "LTE_remote_identity":
            vpn.LTE_remote_identity,
            "cloud_external_interface":
            vpn.cloud_external_interface,
            "cloud_local_address":
            vpn.cloud_local_address,

            #   "network_segment":vpn.network_segment,
            "phase1_dh_group":
            vpn.phase1_dh_group,
            "phase1_authentication_algorithm":
            vpn.phase1_authentication_algorithm,
            "encryption_algophase1_encryption_algorithmrithm":
            vpn.phase1_encryption_algorithm,
            "phase1_pre_shared_key":
            vpn.phase1_pre_shared_key,
            "phase1_dead_peer_detection_nterval":
            vpn.phase1_dead_peer_detection_nterval,
            "phase1_dead_peer_detection_threshold":
            vpn.phase1_dead_peer_detection_threshold,
            "phase2_authentication_algorithm":
            vpn.phase2_authentication_algorithm,
            "phase2_encryption_algorithm":
            vpn.phase2_encryption_algorithm,
            "phase2_perfect_forward_secrecy_keys":
            vpn.phase2_perfect_forward_secrecy_keys
            #   "ipsec_protocol":vpn.ipsec_protocol
        }
        result.append(single)
    return result


@app.route('/applyVPNtemplate', methods=['POST'])
# @login_required
def applyVPNtemplate():
    VPN_name = request.json['name']
    dest_ip = request.json['ip']
    node_name = request.json['node_name']
    # network_segment = request.json['network_segment']
    nodesinfo = []
    output = open('lte_access.yml', 'a+')

    tmp = db_session.query(VPN).filter_by(name=VPN_name).first()

    str = tmp.name
    #按行写入到指定的config文件中
    inputline = "set security zones security-zone" + tmp.name + "address-book address" + tmp.name + "-2"
    print(inputline)
    # output.write(inputline)

    output.close()

    return jsonify(errmsg="success", data=json.dumps(nodesinfo))


# @app.route('/control_path_nodes', methods=['GET'])
# # @login_required
# def getControlPathinfo():
#     nodesinfo = []
#     #按行将获取到的配置信息写入xml文件中
#     output = open('interface.txt', 'w')
#     ff = subprocess.check_output("salt '*' test.ping", shell=True)
#     # print(ff)
#     # infoget = os.popen("salt 'cpe*' junos.rpc 'get-interface-information' '/home/user/interface.xml' interface_name='ge-0/0/0.0' terse=True")
#     # for line in os.popen("salt 'cpe*' junos.rpc 'get-interface-information' interface_name='ge-0/0/0.0' terse=True"):
#     for line in ff:
#         output.write(line)
#     output.close()
#     #按行读取保存好了的xml文件
#     flag = 0
#     node_name = None
#     node_state = None
#     read_file = open('interface.txt', 'r')
#     d = dict()
#     for line in read_file.readlines():
#         d1 = dict()
#         if flag % 2 == 0:
#             d['node_name'] = line.strip().strip(':')
#             # print(type(d['node_name']))
#             str_node = "salt '" + d['node_name'] + "' grains.item os --output=json"
#             node_name = d['node_name']
#             fff = subprocess.check_output(str_node, shell=True)
#             node_info = json.loads(fff)
#             # print("node info type is ",node_info[node_name],d['node_name'])
#             # print("node info type is ",node_info[node_name]['os'])
#             node_type = node_info[node_name]['os']
#             print("node type is ", node_type)
#             if node_type != "proxy":
#                 d['node_type'] = "non-agent"
#             else:
#                 d['node_type'] = "agent"
#         if flag % 2 == 1:
#             if line.strip() == "True":
#                 d['node_state'] = "up"
#             else:
#                 d['node_state'] = "down"
#             d1 = d.copy()
#             nodesinfo.append(d1)
#             print(nodesinfo)
#         flag = flag + 1
#         # print(nodesinfo)
#     return jsonify(errmsg="success", data=json.dumps(nodesinfo))


# @app.route('/traffic_path_nodes', methods=['GET'])
# @login_required
# def getTrafficPathinfo():
#     nodesinfo_basic = []
#     nodesinfo_full = []
#     nodesinfo_result = []
#     #获取cpe节点名称
#     output = open('cpeinfo.txt', 'w')
#     all_cpes = []
#     test_ping_info = subprocess.check_output("salt '*' test.ping", shell=True)
#     for line in test_ping_info:
#         output.write(line)
#     output.close()
#     cpe_name = None
#     read_file = open('cpeinfo.txt', 'r')
#     d_cpe = dict()
#     for line in read_file.readlines():
#         d1 = dict()
#         if "cpe" in line:
#             d_cpe['name'] = line.strip().strip(':')
#             cpe_name = d_cpe['name']
#             all_cpes.append(cpe_name)
#     print(all_cpes)
#     read_file.close()
#     #获得cpe所有节点信息之后，遍历cpe节点连接的节点
#     all_cpes_conn = []
#     for cpe in all_cpes:
#         # str = "salt '"+ cpe + "' junos.rpc 'get-ike-active-peers-information' --output=json"
#         str = "salt 'cpeCloud' junos.rpc 'get-ike-active-peers-information' --output=json"
#         cpes_json_dup = subprocess.check_output(str, shell=True)
#         cpes_json_dup = cpes_json_dup.strip()
#         cpe_json = cpes_json_dup
#         print(cpe_json)
#         vmx_dict = json.loads(cpe_json)
#         print(type(vmx_dict))
#         for i in range(
#                 len(vmx_dict['cpeCloud']['rpc_reply'][
#                     'ike-active-peers-information']['ike-active-peers'])):
#             d1 = dict()
#             d1['ip'] = vmx_dict['cpeCloud']['rpc_reply'][
#                 'ike-active-peers-information']['ike-active-peers'][i][
#                     'ike-sa-remote-address']
#             d1['name'] = vmx_dict['cpeCloud']['rpc_reply'][
#                 'ike-active-peers-information']['ike-active-peers'][i][
#                     'ike-ike-id']
#             equ_name = d1['name']
#             if "agent" in equ_name:
#                 str = "salt '" + d1['name'] + "' junos.rpc 'get-pfe-statistics' --output=json"
#                 equ_in_out = subprocess.check_output(str, shell=True)
#                 equ_dict = json.loads(equ_in_out)
#                 d1['input_pps'] = int(equ_dict[equ_name]['rpc_reply'][
#                     'pfe-statistics']['pfe-traffic-statistics']['input-pps'])
#                 print("input pps is ", type(d1['input_pps']))
#                 # if d1['input_pps'] <= 10:
#                 #     d1['input_pps'] = 1
#                 # elif d1['input_pps'] >10 and d1['input_pps'] <= 100 :
#                 #     d1['input_pps'] = 2
#                 # elif d1['input_pps'] > 100 and d1['input_pps'] <= 1000 :
#                 #     d1['input_pps'] = 3
#                 # else:
#                 #     d1['input_pps'] = 4

#                 d1['output_pps'] = int(equ_dict[equ_name]['rpc_reply'][
#                     'pfe-statistics']['pfe-traffic-statistics']['output-pps'])
#                 print("output pps is ", type(d1['output_pps']))
#             # if d1['output_pps'] <= 10:
#             #     d1['output_pps'] = 1
#             # elif d1['output_pps'] >10 and d1['output_pps'] <= 100 :
#             #     d1['output_pps'] = 2
#             # elif d1['output_pps'] > 100 and d1['output_pps'] <= 1000 :
#             #     d1['output_pps'] = 3
#             # else:
#             #     d1['output_pps'] = 4
#             nodesinfo_basic.append(d1)
#     # cpe_cloud_json_dup = subprocess.check_output("salt 'cpeCloud' junos.rpc 'get-ike-active-peers-information' --output=json", shell=True)
#     # cpe_cloud_json_dup = cpe_cloud_json_dup.strip()
#     # # print cpe_cloud_json, type(cpe_cloud_json)
#     # # cpe_cloud_json = cpe_cloud_json_dup[0: len(cpe_cloud_json_dup)/2]
#     # cpe_cloud_json = cpe_cloud_json_dup
#     # print cpe_cloud_json
#     # vmx_dict = json.loads(cpe_cloud_json)
#     # print type(vmx_dict)
#     # for i in range(len(vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'])):
#     #     d1 = dict()
#     #     d1['ip'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-sa-remote-address']
#     #     d1['name'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-ike-id']
#     #     nodesinfo_basic.append(d1)
#     print(nodesinfo_basic)
#     # for j in range(len(nodesinfo_basic)):
#     #     d3 = dict()
#     #     str = "salt '"+ nodesinfo_basic[j]['name']+"' junos.rpc 'get-ike-active-peers-information' --output=json"
#     #     # child_nodes_json = os.popen(str)
#     #     child_nodes_json = subprocess.check_output(str, shell=True)
#     #     chiled_nodes_dict = json.loads(child_nodes_json)
#     #     d3['switch'] = nodesinfo_basic[j]
#     #     for k in range(len(nodesinfo_basic[j]['name']['cpeCloud']
#     #     ['rpc_reply']['ike-active-peers-information']['ike-active-peers'])):
#     #         d2 = dict()
#     #         d2['ip'] = nodesinfo_basic[j]['name']['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][k]['ike-sa-remote-address']
#     #         d2['name'] = nodesinfo_basic[j]['name']['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][k]['ike-ike-id']
#     #         nodesinfo_full[k].append(d2)
#     #     d3['devices'] = nodesinfo_full[k]
#     #     nodesinfo_result.append(d3)
#     #     nodesinfo_full.clear()

#     return jsonify(errmsg="success", data=json.dumps(nodesinfo_basic))


# @app.route('/apply_vpn_template', methods=['POST'])
# # @login_required
# def applyVPNtemplate_1():
#     global LASTAPPLY_TID
#     tid = request.json['tid']
#     dest_ip = request.json['ip']
#     node_name = request.json['node_name']
#     output = open('lte_centor.yml', 'w')
#     cont = []
#     for line in jinja_centor_test(tid):
#         cont.append(line)
#         output.write(line)
#     output.close()
#     # print("cont is ",cont)
#     output = open('lte_access.yml', 'w')
#     cont = []
#     for line in jinja_access_test(tid):
#         cont.append(line)
#         output.write(line)
#     output.close()
#     node_name = str(node_name)
#     LASTAPPLY_TID = tid
#     # device_name = request.json['device_name']
#     device_name1 = "Agent-2"
#     device_name2 = "cpe1"
#     tmp = db_session.query(VPN).filter_by(tid=tid).first()
#     #拿到对应的模板
#     lines = []
#     output = open('lte_access.yml', 'r')
#     flag = 0
#     for line in output.readlines():
#         if flag == 1:
#             line = line + dest_ip
#             flag = flag + 1
#             lines.append(line)
#             continue
#         if flag == 7:
#             line = line.strip("\n") + "'" + node_name + "'" + "\n"
#             flag = flag + 1
#             lines.append(line)
#             continue
#         flag = flag + 1
#         lines.append(line)
#     output.close()
#     print("lines is", lines)
#     s = ''.join(lines)
#     f = open('lte_access.yml', 'w')
#     f.write(s)
#     f.close()
#     ff = subprocess.check_output(
#         "cp lte_centor.yml /srv/salt/base/lte_centor.yml", shell=True)
#     f = subprocess.check_output(
#         "cp lte_access.yml /srv/salt/base/lte_access.yml", shell=True)
#     str_access = "salt " + node_name + " cp.get_file salt://lte_access.yml /etc/ansible/lte_access.yml"
#     cp_access = subprocess.check_output(str_access, shell=True)
#     str_centor = "salt " + node_name + " cp.get_file salt://lte_centor.yml /etc/ansible/lte_centor.yml"
#     cp_centor = subprocess.check_output(str_centor, shell=True)

#     run_access = "salt " + node_name + " cmd.run 'ansible-playbook -i lte_access.yml customize_lte_access_vpn.yml' cwd='/etc/ansible'"
#     run_yml_access = subprocess.check_output(
#         run_access, shell=True, stderr=subprocess.STDOUT)
#     run_centor = "salt " + node_name + " cmd.run 'ansible-playbook -i lte_centor.yml customize_lte_centor_vpn.yml' cwd='/etc/ansible'"
#     run_yml_centor = subprocess.check_output(
#         run_centor, shell=True, stderr=subprocess.STDOUT)

#     # print(tmp.network_segment)

#     #调用命令行下发配置

#     strerrmsg = run_yml_centor + run_yml_access

#     if "failed=0" in strerrmsg:
#         return jsonify(errmsg="success", status=0)
#     elif "failed=1" in strerrmsg:
#         return jsonify(errmsg=strerrmsg, status=-1)
#     else:
#         return jsonify(errmsg=strerrmsg, status=1)

#     # return jsonify(errmsg = "success")


@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()


@app.route('/testjinja_centor', methods=['GET'])
# @login_required
def jinja_centor_test(tid):
    # tid = request.json['tid']
    tmp = db_session.query(VPN).filter_by(tid=tid).first()
    hub_ip = str(tmp.LTE_cloudGW)
    minion_id = str(tmp.tid)
    ext_interface = str(tmp.cloud_external_interface)
    local_identity = str(tmp.LTE_remote_identity)
    remote_identity = str(tmp.LTE_local_identity)
    local_address = str(tmp.cloud_local_address)

    ike_auth_algorithm = str(tmp.phase1_authentication_algorithm)
    ike_enc_algorithm = str(tmp.phase1_encryption_algorithm)
    dh_group = str(tmp.phase1_dh_group)
    shared_secret = str(tmp.phase1_pre_shared_key)
    DPD_interval = str(tmp.phase1_dead_peer_detection_nterval)
    DPD_threshold = str(tmp.phase1_dead_peer_detection_threshold)

    ipsec_auth_algorithm = str(tmp.phase2_authentication_algorithm)
    ipsec_enc_algorithm = str(tmp.phase2_encryption_algorithm)
    PFS_keys = str(tmp.phase2_perfect_forward_secrecy_keys)

    d = dict()
    d["hub_ip"] = hub_ip
    d["minion_id"] = minion_id
    d["ext_interface"] = ext_interface
    d["local_identity"] = local_identity
    d["remote_identity"] = remote_identity
    d["local_address"] = local_address
    d["ike_auth_algorithm"] = ike_auth_algorithm
    d["ike_enc_algorithm"] = ike_enc_algorithm
    d["dh_group"] = dh_group
    d["shared_secret"] = shared_secret
    d["DPD_interval"] = DPD_interval
    d["DPD_threshold"] = DPD_threshold
    d["ipsec_auth_algorithm"] = ipsec_auth_algorithm
    d["ipsec_enc_algorithm"] = ipsec_enc_algorithm
    d["PFS_keys"] = PFS_keys

    # d["hub_ip"]="112.35.30.67"
    # d["minion_id"]="22"
    # d["ext_interface"]="ge-0/0/0.0"
    # d["local_identity"]="CGW-2"
    # d["remote_identity"]="LTE-node-2"
    # d["local_address"]="10.112.44.113"
    # d["ike_auth_algorithm"]="sha1"
    # d["ike_enc_algorithm"]="aes-128-cbc"
    # d["dh_group"]="group2"
    # d["shared_secret"]="ascii-text $ABC123"
    # d["DPD_interval"]="10"
    # d["DPD_threshold"]="3"
    # d["ipsec_auth_algorithm"]="hmac-sha1-96"
    # d["ipsec_enc_algorithm"]="aes-128-cbc"
    # d["PFS_keys"]="group2"

    return render_template('lte_centor.yml', **d)


@app.route('/testjinja_access', methods=['GET'])
# @login_required
def jinja_access_test(tid):
    # tid = request.json['tid']
    tmp = db_session.query(VPN).filter_by(tid=tid).first()
    # hub_ip = str(tmp.LTE_cloudGW)
    minion_id = str(tmp.tid)
    CLOUD_GW = str(tmp.LTE_cloudGW)
    ext_interface = str(tmp.LTE_external_interface)
    # local_identity = str(tmp.LTE_local_identity)
    remote_identity = str(tmp.LTE_remote_identity)
    # local_address = str(tmp.cloud_local_address)

    ike_auth_algorithm = str(tmp.phase1_authentication_algorithm)
    ike_enc_algorithm = str(tmp.phase1_encryption_algorithm)
    dh_group = str(tmp.phase1_dh_group)
    shared_secret = str(tmp.phase1_pre_shared_key)
    DPD_interval = str(tmp.phase1_dead_peer_detection_nterval)
    DPD_threshold = str(tmp.phase1_dead_peer_detection_threshold)

    ipsec_auth_algorithm = str(tmp.phase2_authentication_algorithm)
    ipsec_enc_algorithm = str(tmp.phase2_encryption_algorithm)
    PFS_keys = str(tmp.phase2_perfect_forward_secrecy_keys)

    d = dict()
    # "hub_ip":hub_ip,
    d["minion_id"] = minion_id
    d["CLOUD_GW"] = CLOUD_GW
    d["ext_interface"] = ext_interface
    # "local_identity"=local_identity,
    d["remote_identity"] = remote_identity
    # "local_address"=local_address,
    d["ike_auth_algorithm"] = ike_auth_algorithm
    d["ike_enc_algorithm"] = ike_enc_algorithm
    d["dh_group"] = dh_group
    d["shared_secret"] = shared_secret
    d["DPD_interval"] = DPD_interval
    d["DPD_threshold"] = DPD_threshold
    d["ipsec_auth_algorithm"] = ipsec_auth_algorithm
    d["ipsec_enc_algorithm"] = ipsec_enc_algorithm
    d["PFS_keys"] = PFS_keys

    return render_template('lte_access.yml', **d)

# @app.route('/apply_utm_template', methods = ['POST'])
# @login_required
# def applyUTMtemplate_1():
#     global LASTAPPLY_UTM
#     tid = request.json['tid']
#     node_ip = request.json['ip']
#     node_name = request.json['node_name']
#     output = open('lte_utm.yml','w')
#     cont = []
#     for line in jinja_utm(tid):
#         cont.append(line)
#         output.write(line)
#     output.close()

#     LASTAPPLY_UTM = tid
#     tmp = db_session.query(UTM).filter_by(tid = tid).first()

#     lines = []
#     output = open('lte_utm.yml','r')
#     flag = 0
#     for line in output.readlines():
#         if flag == 1:
#             line = line + node_ip
#             flag = flag + 1
#             lines.append(line)
#             continue
#         flag = flag + 1
#         lines.append(line)
#     output.close()
#     s = ''.join(lines)
#     f = open('lte_utm.yml','w')
#     f.write(s)
#     f.close()
#     ff = subprocess.check_output(
#         "cp lte_utm.yml /srv/salt/base/lte_utm.yml", shell=True)
#     str_utm = "salt " + node_name + " cp.get_file salt://lte_utm.yml /etc/ansible/lte_utm.yml"
#     cp_access = subprocess.check_output(str_utm, shell=True)
#     run_utm = "salt "+node_name+" cmd.run 'ansible-playbook -i lte_utm.yml utm-config.yml' cwd='/etc/ansible'"
#     run_yml_utm = subprocess.check_output(
#         run_utm, shell=True, stderr=subprocess.STDOUT)

#     strerrmsg = run_yml_utm

#     if "failed=0" in strerrmsg:
#         return jsonify(errmsg="success", status=0)
#     elif "failed=1" in strerrmsg:
#         return jsonify(errmsg=strerrmsg, status=-1)
#     else:
#         return jsonify(errmsg=strerrmsg, status=1)































nodesinfo = [
        {'node_name':'cpe1','node_type':'agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]},
        {'node_name':'cpeCloud','node_type':'agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]},
        {'node_name':'LTE-node2-agent','node_type':'agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]},
        {'node_name':'Agent-1','node_type':'non-agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]},
        {'node_name':'Agent-2','node_type':'non-agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]},
        {'node_name':'LTE-node-2','node_type':'non-agent','node_state':'up','vpn':'down','utm':'down','idp':'down','vpn_id' : 0 ,'utm_id':0,'idp_id':0, 'vpn_tem':[
    {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
    {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
    {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
], 'utm_tem':[
    {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
    {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
    {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
], 'idp_tem':[
    {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
    {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
    {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
]}
    ]
# VPN_tem = [
#     {'tid':1,'name':'vpn_1','applied':False,'type':'VPN'},
#     {'tid':2,'name':'vpn_2','applied':False,'type':'VPN'},
#     {'tid':3,'name':'vpn_3','applied':False,'type':'VPN'}
# ]

# UTM_tem = [
#     {'tid':1,'name':'utm_1','applied':False,'type':'UTM'},
#     {'tid':2,'name':'utm_2','applied':False,'type':'UTM'},
#     {'tid':3,'name':'utm_3','applied':False,'type':'UTM'}
# ]

# IDP_tem = [
#     {'tid':1,'name':'idp_1','applied':False,'type':'IDP'},
#     {'tid':2,'name':'idp_2','applied':False,'type':'IDP'},
#     {'tid':3,'name':'idp_3','applied':False,'type':'IDP'}
# ]
@app.route('/api_templates/<switchname>')
@login_required
def api_templates(switchname):
    global LASTAPPLY_TID
    for node in nodesinfo:
        if node['node_name'] == switchname:
            LASTAPPLY_TID = node['vpn_id']
    for t in VPN_tem:
        print(t['applied'])
        t['applied'] = False
    for t in VPN_tem:
        if t['tid'] == LASTAPPLY_TID:
            t['applied'] = True
        else:
            t['applied'] = False
        
    return jsonify(errmsg = "success",data=VPN_tem)
@app.route('/api_templates/VPN/<switchname>')
@login_required
def api_templates_vpn(switchname):
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['node_name'])
            print(node['vpn_id'])
            for t in node['vpn_tem']:
                print(t['applied'])
                if t['tid'] == node['vpn_id']:
                    t['applied'] = True
                else:
                    t['applied'] = False
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['vpn_tem'])
            return jsonify(errmsg = "success", data = node['vpn_tem'])
    # return jsonify(errmsg = "success",data= nodesinfo[])
@app.route('/apply_vpn_template',methods=['POST'])
@login_required
def applyVPNtemplate_1():
    tid = request.json['tid']
    node_name = request.json['node_name']
    for node in nodesinfo:
        if node['node_name'] == node_name:
            node['vpn_id'] = tid
            node['vpn'] = 'up'
            for t in node['vpn_tem']:
                if t['tid'] == tid:
                    t['applied'] = True
    return jsonify(errmsg = "success", status=0)
@app.route('/api_templates/UTM/<switchname>')
@login_required
def api_templates_utm(switchname):
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['node_name'])
            print(node['utm_id'])
            for t in node['utm_tem']:
                print(t['applied'])
                if t['tid'] == node['utm_id']:
                    t['applied'] = True
                else:
                    t['applied'] = False
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['utm_tem'])
            return jsonify(errmsg = "success", data = node['utm_tem'])
@app.route('/apply_utm_template',methods=['POST'])
@login_required
def applyUTMtemplate_1():
    tid = request.json['tid']
    node_name = request.json['node_name']
    for node in nodesinfo:
        if node['node_name'] == node_name:
            node['utm_id'] = tid
            node['utm'] = 'up'
            for t in node['utm_tem']:
                if t['tid'] == tid:
                    t['applied'] = True
    return jsonify(errmsg = "success", status=0)


@app.route('/api_templates/IDP/<switchname>')
@login_required
def api_templates_idp(switchname):
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['node_name'])
            print(node['idp_id'])
            for t in node['idp_tem']:
                print(t['applied'])
                if t['tid'] == node['idp_id']:
                    t['applied'] = True
                else:
                    t['applied'] = False
    for node in nodesinfo:
        if node['node_name'] == switchname:
            print(node['idp_tem'])
            return jsonify(errmsg = "success", data = node['idp_tem'])

@app.route('/apply_idp_template',methods=['POST'])
@login_required
def applyIDPtemplate_2():
    tid = request.json['tid']
    node_name = request.json['node_name']
    for node in nodesinfo:
        if node['node_name'] == node_name:
            node['idp_id'] = tid
            node['idp'] = 'up'
            for t in node['idp_tem']:
                if t['tid'] == tid:
                    t['applied'] = True
    return jsonify(errmsg = "success", status=0)





@app.route('/control_path_nodes',methods = ['GET'])
@login_required
def getControlPathInfo():
    
    return jsonify(errmsg="success", data=json.dumps(nodesinfo))


nodesinfo_basic = [
    {'name':"LTE-node-2",'ip':"125.34.194.7",'input_pps':35,'output_pps':27},
    {'name':"hgw-1",'ip':"125.34.194.8",'input_pps':23,'output_pps':45},
    {'name':"LTE-node-3",'ip':"223.104.254.115",'input_pps':13,'output_pps':14},
    {'name':"ngfw-1",'ip':"112.35.30.69",'input_pps':21,'output_pps':19}
    
]
@app.route('/traffic_path_nodes', methods=['GET'])
@login_required
def getTrafficPathinfo():

    return jsonify(errmsg = "success", data=json.dumps(nodesinfo_basic))

@app.route("/health_checks")
@login_required
def health_checks():
  return render_template('health_checks.html', nodes=nodesinfo_basic)


devices_info = [
    {'node_name':'LTE-node-2','CPU':'35/100','memory':'6400/8000','flow':[5,4,4,3,3,2,4,7,8,10,15,17,18,17,19,16,15,20,15,19,23,19,13,7]},
    {'node_name':'hgw-1','CPU':'35/100','memory':'6400/8000','flow':[5,4,4,3,3,2,4,7,8,10,15,17,18,17,19,16,15,20,15,19,23,19,13,7]},
    {'node_name':'LTE-node-3','CPU':'35/100','memory':'6400/8000','flow':[5,4,4,3,3,2,4,7,8,10,15,17,18,17,19,16,15,20,15,19,23,19,13,7]},
    {'node_name':'ngfw-1','CPU':'35/100','memory':'6400/8000','flow':[5,4,4,3,3,2,4,7,8,10,15,17,18,17,19,16,15,20,15,19,23,19,13,7]}
    

]

@app.route('/health_checks_/<node>', methods = ['GET'])
# @login_required
def show_devices_info(node):
    print(node)
    for device in devices_info:
        if device['node_name'] == node:
            return render_template('device_health_checks.html', device=device)
            # return jsonify(errmsg = "success", data = json.dumps(device))
    return jsonify(errmsg = "no such node!")
