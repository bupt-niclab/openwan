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
from flask import Flask, redirect, render_template, url_for, session, request, flash, jsonify
from .core import HTTPSaltStackClient, ExpiredToken, Unauthorized, JobNotStarted
from .utils import login_url, parse_highstate, NotHighstateOutput, parse_argspec
from .utils import format_arguments, Call, validate_permissions, REQUIRED_PERMISSIONS
from .utils import get_filtered_post_arguments
from flask_admin import Admin
from . import settings
# from flask_sqlalchemy import sqlalchemy
from .database import db_session
from models import Templates,VPN,Probe
from jinja2 import Environment, select_autoescape,Template
# from models import db
# from flask.ext.sqlalchemy import sqlalchemy

# global lastapply_tid = False
LASTAPPLY_TID = False

# Init app

class FlaskHTTPSaltStackClient(HTTPSaltStackClient):

    def get_token(self):
        return session.get('user_token')

template_folder = join(dirname(__file__), 'templates')
static_folder = join(dirname(__file__), 'static')
app = Flask("Controller", template_folder=template_folder, static_folder=static_folder)
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
        print("Couldn't import raven, please install it with '%s'" % install_cmd)
        sys.exit(1)


client = FlaskHTTPSaltStackClient(app.config['API_URL'],
    app.config.get('VERIFY_SSL', True))

from flask_wtf import FlaskForm as Form
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired

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
            user_token = client.login(form['username'].data, form['password'].data)
            if not validate_permissions(user_token['perms']):
                perms = REQUIRED_PERMISSIONS
                msg = 'Invalid permissions,It needs {0} for user {1}'.format(perms, form['username'].data)
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

    return render_template('dashboard.html', minions=minions,
        ok_status=sync_number, jobs=jobs)

@app.route("/minions")
@login_required
def minions_status():
    minions = client.minions()
    minions_status = client.minions_status()

    for minion in minions_status['up']:
        minions.setdefault(minion, {})['state'] = 'up'

    for minion in minions_status['down']:
        minions.setdefault(minion, {})['state'] = 'down'

    jobs = client.select_jobs('state.highstate', minions, with_details=True,
        test=True, default_arguments_values={'test': False})

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

    jobs = client.select_jobs('state.highstate', minions, with_details=True,
        test=False, default_arguments_values={'test': False})

    return render_template('minions_deployments.html', minions=minions, jobs=jobs)


@app.route("/minions/<minion>/do_deploy")
@login_required
def minions_do_deploy(minion):
    jid = client.run('state.highstate', client="local_async",
        tgt=minion)['jid']
    return redirect(url_for('job_result', minion=minion, jid=jid, renderer='highstate'))


@app.route("/minions/<minion>/do_check_sync")
@login_required
def minions_do_check_sync(minion):
    jid = client.run('state.highstate', client="local_async",
        tgt=minion, args=Call(test=True))['jid']
    return redirect(url_for('job_result', minion=minion, jid=jid, renderer='highstate'))

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
            return redirect(url_for('job_result', jid=jid, minion=minion,
                            renderer='raw'))
    elif renderer == 'aggregate':
        aggregate_result = {}

        for minion, minion_return in job['return'].items():
            aggregate_result.setdefault(str(minion_return), []).append(minion)

        missing_minions = set(job['info']['Minions']) - set(job['return'].keys())
        if missing_minions:
            aggregate_result['Missing results'] = missing_minions
        job['aggregate_return'] = aggregate_result
        context['total_minions'] = sum(len(minions) for minions in aggregate_result.values())

    if not job:
        return "Unknown jid", 404
    return render_template('job_result_{0}.html'.format(renderer), job=job, minion=minion,
                           renderer=renderer, **context)

@app.route("/templates")
@login_required
def templates():
    # master_config = client.run('config.values', client="wheel")['data']['return']
    # if not master_config.get('templates'):
    #     master_config['templates'] = {}
    tmp = db_session.query(VPN).all()

    # return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))


    return render_template("templates.html", templates=tmp)

@app.route("/api_templates/<switchname>")
# @login_required
def api_templates(switchname):
  global LASTAPPLY_TID
  tmp = db_session.query(VPN).all()
  tmp_dict = VPN2dict(tmp)
  for t in tmp_dict:
      if t['tid'] == LASTAPPLY_TID:
          t['applied'] = True
      else:
          t['applied'] = False
  # data = VPN2dict(tmp)
  # data[0]['applied'] = True
  return jsonify(errmsg = "success", data = tmp_dict)


@app.route("/templates/run/<template>")
@login_required
def run_template(template):
    master_config = client.run('config.values', client="wheel")['data']['return']
    template_data = master_config['templates'].get(template)

    if not template_data:
        return "Unknown template", 404

    jid = client.run(template_data['fun'], client="local_async",
        tgt=template_data['tgt'], expr_form=template_data['expr_form'],
        args=Call(**template_data['args']))['jid']

    return redirect(url_for('job_result', jid=jid))

@app.route("/templates/new", methods=['GET', 'POST'])
@login_required
def add_template():
    # form = NewTemplateForm()
    vpn_form = VPNForm()
    # probe_form = ProbeForm()
    if vpn_form.validate_on_submit():   
      # ((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))/24         
      tmp = VPN(vpn_form.name.data, vpn_form.LTE_cloudGW.data, vpn_form.LTE_external_interface.data,vpn_form.LTE_internal_interface.data,
    vpn_form.LTE_local_identity.data, vpn_form.LTE_remote_identity.data,vpn_form.cloud_external_interface.data,
    vpn_form.cloud_internal_interface.data,vpn_form.cloud_local_address.data,
    vpn_form.dh_group.data, vpn_form.authentication_algorithm.data,vpn_form.encryption_algorithm.data, vpn_form.pre_shared_key.data)

      db_session.add(tmp)
      db_session.commit()
      flash('template saved successfully')
      return redirect(url_for('templates'))

    # if probe_form.validate_on_submit():
    #   return jsonify(errmsg="success")      
    #     master_config = client.run('config.values', client="wheel")['data']['return']

    #     BLACKLIST_ARGS = ('csrf_token', 'tgt', 'fun', 'expr_form', 'name', 'description','owner')
    #     args = get_filtered_post_arguments(BLACKLIST_ARGS)

    #     templates = master_config.get('templates', {})
    #     #print templates
    #     templates[form.name.data.strip()] = {
    #         'description': form.description.data.strip(),
    #         'fun': form.fun.data.strip(),
    #         'tgt': form.tgt.data.strip(),
    #         'expr_form': form.expr_form.data.strip(),
    #         'args': args}

    #     client.run('config.apply', client="wheel", key="templates", value=templates)

    #     master_config = client.run('config.values', client="wheel")
        
    #     flash('Template {0} has been successfully saved'.format(form.name.data.strip()))

    #     return redirect(url_for('templates'))
    return render_template("add_template.html", vpn_form=vpn_form)

@app.route("/template/edit/<tid>", methods=['GET', 'POST'])
@login_required
def edit_template(tid):
  tmp = db_session.query(VPN).filter_by(tid=tid).first()
  vpn_form = VPNForm()    
  if request.method == 'GET':
    vpn_form.name.data = tmp.name
    vpn_form.LTE_cloudGW.data = tmp.LTE_cloudGW
    vpn_form.LTE_external_interface.data = tmp.LTE_external_interface
    # vpn_form.LTE_internal_interface.data = tmp.LTE_internal_interface
    vpn_form.LTE_local_identity.data = tmp.LTE_local_identity
    vpn_form.LTE_remote_identity.data = tmp.LTE_remote_identity
    vpn_form.cloud_external_interface.data = tmp.cloud_external_interface
    # vpn_form.cloud_internal_interface.data = tmp.cloud_internal_interface
    vpn_form.cloud_local_address.data = tmp.cloud_local_address
    # vpn_form.network_segment.data = tmp.network_segment
    vpn_form.phase1_dh_group.data = tmp.phase1_dh_group
    vpn_form.phase1_authentication_algorithm.data = tmp.phase1_authentication_algorithm
    vpn_form.phase1_encryption_algorithm.data = tmp.phase1_encryption_algorithm
    vpn_form.phase1_pre_shared_key.data = tmp.phase1_pre_shared_key
    vpn_form.phase1_dead_peer_detection_nterval = tmp.phase1_dead_peer_detection_nterval
    vpn_form.phase1_dead_peer_detection_threshold = tmp.phase1_dead_peer_detection_threshold
    vpn_form.phase2_authentication_algorithm = phase2_authentication_algorithm
    vpn_form.phase2_encryption_algorithm = phase2_encryption_algorithm
    vpn_form.phase2_perfect_forward_secrecy_keys = phase2_perfect_forward_secrecy_keys
    # vpn_form.ipsec_protocol.data = tmp.ipsec_protocol
    # probe_form = ProbeForm()
  
  if vpn_form.validate_on_submit():            
    db_session.delete(tmp)
    db_session.commit()
    print(vpn_form.name.data)
    tmp2 = VPN(vpn_form.name.data,
    vpn_form.LTE_cloudGW.data,
    vpn_form.LTE_external_interface.data,
    vpn_form.LTE_local_identity.data,
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
    vpn_form.phase2_perfect_forward_secrecy_keys)
    print(tmp2)

    db_session.add(tmp2)
    db_session.commit()

    flash('template saved successfully')    
    return redirect(url_for('templates'))

  # if probe_form.validate_on_submit():
  #   return jsonify(errmsg="success")      
  return render_template("edit_template.html", vpn_form=vpn_form, tid=tid)


@app.route("/deployments")
@login_required
def deployments():
    return ""


from flask_wtf import FlaskForm as Form
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired

matchers = [
    ('glob', 'Glob'),
    ('pcre', 'Perl regular expression'),
    ('list', 'List'),
    ('grain', 'Grain'),
    ('grain_pcre', 'Grain perl regex'),
    ('pillar', 'Pillar'),
    ('nodegroup', 'Nodegroup'),
    ('range', 'Range'),
    ('compound', 'Compound')
]
probe_type = [
    ('0','0'),
    ('1','1'),
    ('2','2'),
    ('3','3'),
    ('4','4'),
    ('5','5'),
    ('6','6')
]

hardware_time = [
    ('True', 'True'),
    ('False', 'False')
]
LTE_cloudGW = [
    ('112.35.30.65','112.35.30.65'),
    ('112.35.30.67','112.35.30.67'),
    ('112.35.30.69','112.35.30.69')
]
LTE_external_interface = [
    ('ge-0/0/0','ge-0/0/0'),
    ('ge-0/0/1','ge-0/0/1')
]
LTE_internal_interface = [
    ('ge-0/0/2','ge-0/0/2'),
    ('ge-0/0/1','ge-0/0/1')
]
cloud_internal_interface = [
    ('ge-0/0/1','ge-0/0/1'),
    ('ge-0/0/2','ge-0/0/2')
]
dh_group = [
    ('group1', 'group1'),
    ('group2', 'group2'),
    ('group5', 'group5')
]

phase1_authentication_algorithm = [
    ('md5', 'md5'),
    ('sha-256','sha-256'),
    ('sha1','sha1')
]

phase1_encryption_algorithm = [
    ('3des-cbc','3des-cbc'),
    ('aes-128-cbc','aes-128-cbc'),
    ('aes-192-cbc', 'aes-192-cbc'),
    ('aes-256-cbc','aes-256-cbc'),
    ('des-cbc','des-cbc')
]

phase1_pre_shared_key = [
    ('ascii-text $ABC123','ascii-text $ABC123')
]

ipsec_protocol = [
    ('ah','ah'),
    ('esp','esp')
]
phase2_authentication_algorithm = [
    ('hmac-md5-96','hmac-md5-96'),
    ('hmac-sha1-96','hmac-sha1-96')
]
phase2_encryption_algorithm = [
    ('3des-cbc','3des-cbc'),
    ('aes-128-cbc','aes-128-cbc'),
    ('aes-192-cbc', 'aes-192-cbc'),
    ('aes-256-cbc','aes-256-cbc'),
    ('des-cbc','des-cbc')
]
phase2_perfect_forward_secrecy_keys = [
    ('group1', 'group1'),
    ('group2', 'group2'),
    ('group5', 'group5')
]
class RunForm(Form):
    expr_form = SelectField('matcher', choices=matchers)
    tgt = StringField('target', validators=[DataRequired()])
    fun = StringField('function', validators=[DataRequired()])
    arg= StringField('arg', validators=None)

class ProbeForm(Form):
    owner = StringField('owner', validators=[DataRequired()])#32字符
    test_name = StringField('test-name', validators = [DataRequired])#32字符
    probe_type = SelectField('probe-type', choices=probe_type)#0-6
    data_size = StringField('data-size', validators=[DataRequired])#0-65507
    data_fill = StringField('datafill', validators=[DataRequired])#1-800h 16进制 和data-size要都有或都没有
    destination_port = StringField('destination-port', validators=[DataRequired])#7 或 49160-65535
    dscp_code_point = StringField('dscp-code-point', validators=[DataRequired])#6bits
    hardware_time = SelectField('hardware-timestamp', choices=hardware_time)#yes or no
    history_size = StringField('history-size',validators=[DataRequired])#0-255
    moving_average_size = StringField('moving-average-size', validators=[DataRequired])#0-255
    probe_count = StringField('probe-count', validators=[DataRequired])#1-15
    probe_interval = StringField('probe-interval', validators=[DataRequired])#1-255
    source_address = StringField('source_address', validators=[DataRequired])#接口地址
    target = StringField('target', validators=[DataRequired])#http必须要有，或者用ip
    test_interval = StringField('test-interval', validators=[DataRequired])#0-86400

class VPNForm(Form):
    name = StringField('name', validators=[DataRequired()])#必填
    LTE_cloudGW = SelectField('LTE-cloudGW', choices=LTE_cloudGW)
    LTE_external_interface = SelectField('LTE-external-interface',choices=LTE_external_interface)
    # LTE_internal_interface = SelectField('LTE-internal-interface',choices=LTE_internal_interface)
    LTE_local_identity = StringField('LTE-local-identity',validators=[DataRequired()])
    LTE_remote_identity = StringField('LTE-remote-identity', validators=[DataRequired()])
    cloud_external_interface = StringField('cloud-external-interface',validators=[DataRequired()])
    # cloud_internal_interface = SelectField('cloud-internal-interface', choices=cloud_internal_interface)
    cloud_local_address = StringField('cloud-local-address',validators=[DataRequired()])
    # network_segment = StringField('network-segment', validators=[DataRequired()])#必填
    phase1_dh_group = SelectField('phase1-dh-group',choices=dh_group)
    phase1_authentication_algorithm = SelectField('phase1-authentication-algorithm',choices=phase1_authentication_algorithm)
    phase1_encryption_algorithm = SelectField('phase1-encryption-algorithm',choices=phase1_encryption_algorithm)
    phase1_pre_shared_key = SelectField('phase1-pre-shared-key',choices=phase1_pre_shared_key)
    # ipsec_protocol = SelectField('ipsec-protocol',choices=ipsec_protocol)
    phase1_dead_peer_detection_nterval = StringField('phase1_dead_peer_detection_nterval',validators=[DataRequired])
    phase1_dead_peer_detection_threshold = StringField('phase1_dead_peer_detection_threshold',validators=[DataRequired])
    phase2_authentication_algorithm = SelectField('phase2_authentication_algorithm',choices=phase2_authentication_algorithm)
    phase2_encryption_algorithm = SelectField('phase2_encryption_algorithm',choices=phase2_encryption_algorithm)
    phase2_perfect_forward_secrecy_keys = SelectField('phase2_perfect_forward_secrecy_keys',choices=phase2_perfect_forward_secrecy_keys)
def validate_network_segment(form, field):
  try: 
    startIpSegment = field.data.strip().split('-')[0] # 192.168.1.1/24
    startIp = startIpSegment.split('/')[0]  # 192.168.1.1
    startSubnetMask = startIpSegment.split('/')[1]  # 24

    endIpSegment = field.data.strip().split('-')[1] # 192.168.1.10/24
    endIp = endIpSegment.split('/')[0]   # 192.168.1.10
    endSubnetMask = endIpSegment.split('/')[1]  # 24
  except:
    raise ValidationError("please input correct format like '10.0.0.1/24-10.1.0.0/24'")

  # if form.validators.IPAddress(ipv4=True):

class NewTemplateForm(RunForm):
    name = StringField('name', validators=[DataRequired()])
    description = TextAreaField('description', validators=[DataRequired()])



@app.route('/run', methods=["GET", "POST"])
@login_required
def run():
    form = RunForm()
    if form.validate_on_submit():

        args = get_filtered_post_arguments(('csrf_token', 'tgt', 'fun', 'args','expr_form', 'arg'))
        #print args,"==================================================>"
        jid = client.run(form.fun.data.strip(), client="local_async",
            tgt=form.tgt.data.strip(), arg=form.arg.data.strip(), expr_form=form.expr_form.data.strip(),
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
        new_jid = client.run(job['info']['Function'], client="local_async",
            tgt=job['info']['Target'], expr_form=job['info']['Target-type'],
            args=job['info']['Arguments'])['jid']
    except JobNotStarted:
        msg = "Couldn't redo the job, check salt api log for more details"
        flash(msg, 'error')
        return redirect(url_for('job_result', minion=minion, jid=jid,
            renderer='highstate'))

    return redirect(url_for('job_result', minion=minion, jid=new_jid,
        renderer='highstate'))


@app.route('/doc_search', methods=["POST", "OPTIONS"])
@login_required
def doc_search():
    content = request.json

    arg_specs = client.run('sys.argspec', client='local',
        tgt=content['tgt'].strip(), expr_form=content['expr_form'],
        args=Call(content['fun'].strip()))

    if not arg_specs:
        return jsonify({'error': 'No matching minions found'}), 400

    # Take only first result
    arg_specs = list(arg_specs.values())[0]

    module_function_names = list(arg_specs.keys())

    docs = client.run('sys.doc', client='local', tgt=content['tgt'].strip(),
        expr_form=content['expr_form'], args=Call(*module_function_names))

    # Take only first result
    docs = list(docs.values())[0]

    result = {}

    for module_function_name in module_function_names:
        result[module_function_name] = {
            'spec': parse_argspec(arg_specs[module_function_name]),
            'doc': docs[module_function_name]}

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
    minions_keys = client.run('key.delete', client="wheel", match=key)['data']['return']
    return redirect(url_for('minions_keys'))


@app.route('/keys/reject/<key>')
@login_required
def reject_key(key):
    content = request.json
    client.run('key.reject', client="wheel", match=key)['data']['return']
    return redirect(url_for('minions_keys'))


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
    return render_template("minion_details.html", minion_details=minion_details)

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

    pillar_data = client.run("pillar.items", client="local", tgt=minion)[minion]
    # Make a PR for that
    #pillar_top = client.run("pillar.show_top", client="runner", minion=minion)
    state_top = client.run("state.show_top", client="local", tgt=minion)[minion]
    lowstate = client.run("state.show_lowstate", client="local", tgt=minion)[minion]
    grains = client.run("grains.items", client="local", tgt=minion)[minion]

    return render_template('debug_minion.html', minion=minion,
        pillar_data=pillar_data, state_top=state_top, lowstate=lowstate,
        grains=grains)

@app.route('/wip')
@login_required
def wip():
    return render_template("wip.html")


@app.template_filter("aggregate_len_sort")
def aggregate_len_sort(unsorted_dict):
    return sorted(unsorted_dict.items(), key=lambda x: len(x[1]),
        reverse=True)

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
  scheduler.add_job(run_script, 'interval', start_date=datetime.datetime.now() + datetime.timedelta(seconds=1), minutes=15)
  scheduler.start()

@app.route("/templates/VPN/new", methods = ['POST'])
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
    phase1_authentication_algorithm = request.json['phase1_authentication_algorithm']
    phase1_encryption_algorithm = request.json['phase1_encryption_algorithm']
    phase1_pre_shared_key = request.json['phase1_pre_shared_key']
    phase1_dead_peer_detection_nterval = request.json['phase1_dead_peer_detection_nterval']
    phase1_dead_peer_detection_threshold = request.json['phase1_dead_peer_detection_threshold']
    phase2_authentication_algorithm = request.json['phase2_authentication_algorithm']
    phase2_encryption_algorithm = request.json['phase2_encryption_algorithm']
    phase2_perfect_forward_secrecy_keys = request.json['phase2_perfect_forward_secrecy_keys']
    

    tmp = VPN(vpn_form.name.data,
    vpn_form.LTE_cloudGW.data,
    vpn_form.LTE_external_interface.data,
    vpn_form.LTE_local_identity.data,
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
    vpn_form.phase2_perfect_forward_secrecy_keys)
    print (tmp)
    test = db_session.query(VPN).filter_by(name = VPN_name).first()
    if test.name != None:
        return jsonify(errmsg="primary key conflict", data="1")

    db_session.add(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')

@app.route('/templates/VPN/delete', methods = ['POST'])
@login_required
def del_VPN_template():
    # print(request.json)
    VPN_name = request.json['name']
    # network_segment = request.json['network_segment']
    
    
    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()
    if tmp.name == None:
        return jsonify(errmsg="No such template",data='2')

    db_session.delete(tmp)
    db_session.commit()

    return jsonify(errmsg = "success", data = '0')

@app.route('/templates/VPN/modify', methods = ['POST'])
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
    phase1_authentication_algorithm = request.json['phase1_authentication_algorithm']
    phase1_encryption_algorithm = request.json['phase1_encryption_algorithm']
    phase1_pre_shared_key = request.json['phase1_pre_shared_key']
    phase1_dead_peer_detection_nterval = request.json['phase1_dead_peer_detection_nterval']
    phase1_dead_peer_detection_threshold = request.json['phase1_dead_peer_detection_threshold']
    phase2_authentication_algorithm = request.json['phase2_authentication_algorithm']
    phase2_encryption_algorithm = request.json['phase2_encryption_algorithm']
    phase2_perfect_forward_secrecy_keys = request.json['phase2_perfect_forward_secrecy_keys']

    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()

    db_session.delete(tmp)
    db_session.commit()

    tmp = VPN(vpn_form.name.data,
    vpn_form.LTE_cloudGW.data,
    vpn_form.LTE_external_interface.data,
    vpn_form.LTE_local_identity.data,
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
    vpn_form.phase2_perfect_forward_secrecy_keys)

    db_session.add(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')

@app.route('/templates/VPN/query', methods = ['POST'])
@login_required
def query_VPN_template():
    
    VPN_name = request.json['name']

    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()

    # print (tmp)

    return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))

@app.route('/templates/VPN/all', methods = ['GET'])
@login_required
def query_all_VPN_template():
    
    # VPN_name = request.json['name']

    tmp = db_session.query(VPN).all()


    return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))


def VPN2dict(vpns):
  result = []
  for vpn in vpns:
    single = {
      "tid": vpn.tid,
      "name":vpn.name,
      "network_segment":vpn.network_segment,
      "dh_group":vpn.dh_group,
      "authentication_algorithm":vpn.authentication_algorithm,
      "encryption_algorithm":vpn.encryption_algorithm,
      "pre_shared_key":vpn.pre_shared_key,
      "ipsec_protocol":vpn.ipsec_protocol
    }
    result.append(single)
  return result

@app.route('/applyVPNtemplate',methods = ['POST'])
# @login_required
def applyVPNtemplate():
    VPN_name = request.json['name']
    dest_ip = request.json['ip']
    node_name = request.json['node_name']
    # network_segment = request.json['network_segment']
    nodesinfo = []
    output = open('lte_access.yml','a+')

    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()

    str  = tmp.name
    #按行写入到指定的config文件中 
    inputline = "set security zones security-zone" + tmp.name +"address-book address" + tmp.name + "-2"
    print(inputline)
    # output.write(inputline)
    

    output.close()


    return jsonify(errmsg = "success", data = json.dumps(nodesinfo))

@app.route('/control_path_nodes',methods = ['GET'])
# @login_required
def getControlPathinfo():
    nodesinfo = []
    #按行将获取到的配置信息写入xml文件中 
    output = open('interface.txt','w')
    ff = subprocess.check_output("salt '*' test.ping",shell = True)
    # print(ff)
    # infoget = os.popen("salt 'cpe*' junos.rpc 'get-interface-information' '/home/user/interface.xml' interface_name='ge-0/0/0.0' terse=True")
    # for line in os.popen("salt 'cpe*' junos.rpc 'get-interface-information' interface_name='ge-0/0/0.0' terse=True"):
    for line in ff:
        output.write(line)
    output.close()
    #按行读取保存好了的xml文件 
    flag = 0;
    node_name = None
    node_state = None
    read_file = open('interface.txt','r')
    d = dict()
    for line in read_file.readlines():
        d1 = dict()
        if flag % 2 == 0:
            d['node_name'] = line.strip().strip(':')
            str = "salt '"+d['node_name']+"' grains.item os --output=json"
            node_name = d['node_name']
            fff = subprocess.check_output(str,shell = True)
            node_info = json.loads(fff)
            node_type = node_info[node_name]['os']
            print("node type is ",node_type)
            if node_type != "proxy":
                d['node_type'] = "non-agent"
            else:
                d['node_type'] = "agent"
        if flag % 2 == 1:
            if line.strip() == "True":
                d['node_state'] = "up"
            else:
                d['node_state'] = "down"
            d1 = d.copy()
            nodesinfo.append(d1)
            print(nodesinfo)
        flag = flag + 1
        # print(nodesinfo)
    return jsonify(errmsg = "success", data = json.dumps(nodesinfo))

@app.route('/traffic_path_nodes',methods = ['GET'])
@login_required
def getTrafficPathinfo():
    nodesinfo_basic = []
    nodesinfo_full = []
    nodesinfo_result = []
    #获取cpe节点名称
    output = open('cpeinfo.txt','w')
    all_cpes = []
    test_ping_info = subprocess.check_output("salt '*' test.ping",shell = True)
    for line in test_ping_info:
        output.write(line)
    output.close()
    cpe_name = None
    read_file = open('cpeinfo.txt','r')
    d_cpe = dict()
    for line in read_file.readlines():
        d1 = dict()
        if "cpe" in line:
            d_cpe['name'] = line.strip().strip(':')
            cpe_name = d_cpe['name']
            all_cpes.append(cpe_name)
    print(all_cpes)
    read_file.close()
    #获得cpe所有节点信息之后，遍历cpe节点连接的节点
    all_cpes_conn = []
    for cpe in all_cpes:
        str = "salt '"+ cpe + "' junos.rpc 'get-ike-active-peers-information' --output=json"
        cpes_json_dup = subprocess.check_output(str,shell = True)
        cpes_json_dup = cpes_dup.strip()
        cpe_json = cpes_json_dup
        print(cpe_json)
        vmx_dict = json.loads(cpe_json)
        print(type(vmx_dict))
        for i in range(len(vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'])):
            d1 = dict()      
            d1['ip'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-sa-remote-address']
            d1['name'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-ike-id']
            equ_name = d1['name']
            str = "salt '"+d1['name']+ "' junos.rpc 'get-pfe-statistics' --output=json"
            equ_in_out = subprocess.check_output(str,shell = True)
            equ_dict = json.loads(equ_in_out)
            d1['input_pps'] = int(equ_dict[equ_name]['rpc_reply']['pfe-statistics']['pfe-traffic-statistics']['input-pps'])
            print("input pps is ",type(d1['input_pps']))
            # if d1['input_pps'] <= 10:
            #     d1['input_pps'] = 1
            # elif d1['input_pps'] >10 and d1['input_pps'] <= 100 :
            #     d1['input_pps'] = 2
            # elif d1['input_pps'] > 100 and d1['input_pps'] <= 1000 :
            #     d1['input_pps'] = 3
            # else:
            #     d1['input_pps'] = 4   
                
            d1['output_pps'] = int(equ_dict[equ_name]['rpc_reply']['pfe-statistics']['pfe-traffic-statistics']['output-pps'])
            print("output pps is ",type(d1['output_pps']))
            # if d1['output_pps'] <= 10:
            #     d1['output_pps'] = 1
            # elif d1['output_pps'] >10 and d1['output_pps'] <= 100 :
            #     d1['output_pps'] = 2
            # elif d1['output_pps'] > 100 and d1['output_pps'] <= 1000 :
            #     d1['output_pps'] = 3
            # else:
            #     d1['output_pps'] = 4 
            nodesinfo_basic.append(d1)
    # cpe_cloud_json_dup = subprocess.check_output("salt 'cpeCloud' junos.rpc 'get-ike-active-peers-information' --output=json", shell=True)
    # cpe_cloud_json_dup = cpe_cloud_json_dup.strip()
    # # print cpe_cloud_json, type(cpe_cloud_json)
    # # cpe_cloud_json = cpe_cloud_json_dup[0: len(cpe_cloud_json_dup)/2]
    # cpe_cloud_json = cpe_cloud_json_dup    
    # print cpe_cloud_json
    # vmx_dict = json.loads(cpe_cloud_json)
    # print type(vmx_dict)
    # for i in range(len(vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'])):
    #     d1 = dict()      
    #     d1['ip'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-sa-remote-address']
    #     d1['name'] = vmx_dict['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][i]['ike-ike-id']
    #     nodesinfo_basic.append(d1)
    print nodesinfo_basic
    # for j in range(len(nodesinfo_basic)):
    #     d3 = dict()        
    #     str = "salt '"+ nodesinfo_basic[j]['name']+"' junos.rpc 'get-ike-active-peers-information' --output=json"
    #     # child_nodes_json = os.popen(str)
    #     child_nodes_json = subprocess.check_output(str, shell=True)
    #     chiled_nodes_dict = json.loads(child_nodes_json)
    #     d3['switch'] = nodesinfo_basic[j]
    #     for k in range(len(nodesinfo_basic[j]['name']['cpeCloud']
    #     ['rpc_reply']['ike-active-peers-information']['ike-active-peers'])):
    #         d2 = dict()        
    #         d2['ip'] = nodesinfo_basic[j]['name']['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][k]['ike-sa-remote-address']
    #         d2['name'] = nodesinfo_basic[j]['name']['cpeCloud']['rpc_reply']['ike-active-peers-information']['ike-active-peers'][k]['ike-ike-id']
    #         nodesinfo_full[k].append(d2)
    #     d3['devices'] = nodesinfo_full[k]
    #     nodesinfo_result.append(d3)
    #     nodesinfo_full.clear()
    

    return jsonify(errmsg = "success", data = json.dumps(nodesinfo_basic))

@app.route('/apply_vpn_template', methods=['POST'])
# @login_required
def applyVPNtemplate_1():
    global LASTAPPLY_TID
    tid = request.json['tid']
    dest_ip = str(request.json['ip'])
    node_name = str(request.json['node_name'])
    LASTAPPLY_TID = tid
    # device_name = request.json['device_name']
    device_name1 = "Agent-2"
    device_name2 = "cpe1"
    tmp = db_session.query(VPN).filter_by(tid = tid).first()
    #拿到对应的模板 
    lines = []
    output = open('lte_access.yml','a+')
    flag = 0
    for line in output.readlines():
        lines.append(line)
    output.close()
    pirnt lines
    lines.insert(1,dest_ip)
    str = "local_identity = '"+node_name+"'"
    lines.insert(7,str)
    s = ''+join(lines)
    f=open('lte_access.yml','w')
    f.write(s)
    f.close()
    ff = subprocess.check_output("cp -f lte_centor.yml /srv/salt/base/let_centor.yml",shell = True)
    f = subprocess.check_output("cp -f lte_access.yml /srv/salt/base/let_access.yml",shell = True)
    str_access = "salt "+node_name+" cp.get_file salt://lte_access.yml /etc/ansible/lte_access.yml"
    cp_access = subprocess.check_output(str_centor,shell = True)
    str_centor = "salt "+node_name+" cp.get_file salt://lte_centor.yml /etc/ansible/lte_centor.yml"
    cp_centor = subprocess.check_output(str_centor,shell = True)

    run_access = "salt "+node_name+" cmd.run 'ansible-playbook -i lte_access.yml customize_lte_access_vpn.yml' cwd='/etc/ansible'"
    run_yml_access = subprocess.check_output(run_access,shell = True，stderr = subprocess.STDOUT)
    run_centor = "salt "+node_name+" cmd.run 'ansible-playbook -i lte_centor.yml customize_lte_centor_vpn.yml' cwd='/etc/ansible'"
    run_yml_centor = subprocess.check_output(run_centor,shell = True, stderr = subprocess.STDOUT)

    
    # print(tmp.network_segment)

   
    

    #调用命令行下发配置
    
    strerrmsg = run_yml_centor + run_yml_access


    if "failed=0" in strerrmsg:
        return jsonify(errmsg = "success", status = 0)
    elif "failed=1" in strerrmsg:
        return jsonify(errmsg = strerrmsg , status = -1)
    else:
        return jsonify(errmsg = strerrmsg , status = 1)
        

    # return jsonify(errmsg = "success") 


@app.teardown_request
def shutdown_session(exception=None):
  db_session.remove()

@app.route('/keys/reject/<key>')
@login_required
def reject_key(key):
    content = request.json
    client.run('key.reject', client="wheel", arg = key)['data']['return']
    return redirect(url_for('minios_keys'))


@app.route('/testjinja_centor',methods = ['POST'])
@login_required
def jinja_centor_test():
    tid = request.json['tid']
    tmp = db_session.query(VPN).filter_by(tid = tid).first()
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

    dict = [
        "hub_ip":hub_ip,
        "minion_id"=minion_id,
        "ext_interface"=ext_interface,
        "local_identity"=local_identity,
        "remote_identity"=remote_identity,
        "local_address"=local_address,
        "ike_auth_algorithm"=ike_auth_algorithm,
        "ike_enc_algorithm"=ike_enc_algorithm,
        "dh_group"=dh_group,
        "shared_secret"=shared_secret,
        "DPD_interval"=DPD_interval,
        "DPD_threshold"=DPD_threshold,
        "ipsec_auth_algorithm"=ipsec_auth_algorithm,
        "ipsec_enc_algorithm"=ipsec_enc_algorithm,
        "PFS_keys"=PFS_keys
    ]

    return render_template('lte_centor.yml', **dict)

@app.route('/testjinja_access',methods = ['POST'])
@login_required
def jinja_access_test():
    tid = request.json['tid']
    tmp = db_session.query(VPN).filter_by(tid = tid).first()
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

    dict = [
        # "hub_ip":hub_ip,
        "minion_id"=minion_id,
        "CLOUD_GW"=CLOUD_GW
        "ext_interface"=ext_interface,
        # "local_identity"=local_identity,
        "remote_identity"=remote_identity,
        # "local_address"=local_address,
        "ike_auth_algorithm"=ike_auth_algorithm,
        "ike_enc_algorithm"=ike_enc_algorithm,
        "dh_group"=dh_group,
        "shared_secret"=shared_secret,
        "DPD_interval"=DPD_interval,
        "DPD_threshold"=DPD_threshold,
        "ipsec_auth_algorithm"=ipsec_auth_algorithm,
        "ipsec_enc_algorithm"=ipsec_enc_algorithm,
        "PFS_keys"=PFS_keys
    ]

    return render_template('lte_access.yml', **dict)

@app.route('/apply_centor',methods = ['GET'])
@login_required
def apply_jinja_centor():
    ff = subprocess.check_output("cp -f lte_centor.yml /srv/salt/base/let_centor.yml",shell = True)
    f = subprocess.check_output("cp -f lte_access.yml /srv/salt/base/let_access.yml",shell = True)
    run_yml = subprocess.check_output(,shell = True)

    return jsonify(errmsg = 'success')
