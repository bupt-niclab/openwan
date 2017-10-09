#coding=utf-8

import sys
import json

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
# from models import db
# from flask.ext.sqlalchemy import sqlalchemy



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
    probe_form = ProbeForm()
    if vpn_form.validate_on_submit():
      print(vpn_form.name.data)
      print(vpn_form.network_segment.data)
      print(vpn_form.dh_group.data)    
      print(vpn_form.authentication_algorithm.data)    
      print(vpn_form.encryption_algorithm.data)              
      tmp = VPN(vpn_form.name.data, vpn_form.network_segment.data,vpn_form.dh_group.data, vpn_form.authentication_algorithm.data,vpn_form.encryption_algorithm.data, vpn_form.pre_shared_key.data,vpn_form.ipsec_protocol.data)
      print (tmp)
      # test = db_session.query(VPN).filter_by(name = vpn_form.name.data).first()
      # if test.name != None:
      #   return jsonify(errmsg="primary key conflict", data="1")

      db_session.add(tmp)
      db_session.commit()

      return jsonify(errmsg="success", data='0')

    if probe_form.validate_on_submit():
      return jsonify(errmsg="success")      
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

dh_group = [
    ('group1', 'group1'),
    ('group2', 'group2'),
    ('group5', 'group5')
]

authentication_algorithm = [
    ('md5', 'md5'),
    ('sha-256','sha-256'),
    ('sha1','sha1')
]

encryption_algorithm = [
    ('3des-cbc','3des-cbc'),
    ('aes-128-cbc','aes-128-cbc'),
    ('aes-192-cbc', 'aes-192-cbc'),
    ('aes-256-cbc','aes-256-cbc'),
    ('des-cbc','des-cbc')
]

pre_shared_key = [
    ('ascii-text $ABC123','ascii-text $ABC123')
]

ipsec_protocol = [
    ('ah','ah'),
    ('esp','esp')
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
    network_segment = StringField('network-segment', validators=[DataRequired()])#必填
    dh_group = SelectField('dh-group',choices=dh_group)
    authentication_algorithm = SelectField('authentication-algorithm',choices=authentication_algorithm)
    encryption_algorithm = SelectField('encryption-algorithm',choices=encryption_algorithm)
    pre_shared_key = SelectField('pre-shared-key',choices=pre_shared_key)
    ipsec_protocol = SelectField('ipsec-protocol',choices=ipsec_protocol)

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
    network_segment = request.json['network_segment']
    dh_group = request.json['dh_group']
    authentication_algorithm = request.json['authentication_algorithm']
    encryption_algorithm = request.json['encryption_algorithm']
    pre_shared_key = request.json['pre_shared_key']
    ipsec_protocol = request.json['ipsec_protocol']

    tmp = VPN(VPN_name,network_segment,dh_group,authentication_algorithm,encryption_algorithm,pre_shared_key,ipsec_protocol)
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
    network_segment = request.json['network_segment']
    
    
    tmp = db_session.query(VPN).filter_by(name = VPN_name, network_segment = network_segment).first()
    if tmp.name == None:
        return jsonify(errmsg="No such template",data='2')

    db_session.delete(tmp)
    db_session.commit()

    return jsonify(errmsg = "success", data = '0')

@app.route('/templates/VPN/modify', methods = ['POST'])
@login_required
def modify_VPN_template():
    
    VPN_name = request.json['name']
    network_segment = request.json['network_segment']
    dh_group = request.json['dh_group']
    authentication_algorithm = request.json['authentication_algorithm']
    encryption_algorithm = request.json['encryption_algorithm']
    pre_shared_key = request.json['pre_shared_key']
    ipsec_protocol = request.json['ipsec_protocol']

    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()

    db_session.delete(tmp)
    db_session.commit()

    tmp = VPN(VPN_name,network_segment,dh_group,authentication_algorithm,encryption_algorithm,pre_shared_key,ipsec_protocol)

    db_session.add(tmp)
    db_session.commit()

    return jsonify(errmsg="success", data='0')

@app.route('/templates/VPN/query', methods = ['POST'])
@login_required
def query_VPN_template():
    
    VPN_name = request.json['name']

    tmp = db_session.query(VPN).filter_by(name = VPN_name).first()

    # print tmp

    return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))

@app.route('/templates/VPN/all', methods = ['GET'])
@login_required
def query_all_VPN_template():
    
    # VPN_name = request.json['name']

    tmp = db_session.query(VPN).all()


    return jsonify(errmsg = "success", data = json.dumps(tmp ,default = VPN2dict))


def VPN2dict(vpn):
    return {
        "name":vpn.name,
        "network_segment":vpn.network_segment,
        "dh_group":vpn.dh_group,
        "authentication_algorithm":vpn.authentication_algorithm,
        "encryption_algorithm":vpn.encryption_algorithm,
        "pre_shared_key":vpn.pre_shared_key,
        "ipsec_protocol":vpn.ipsec_protocol

}

@app.teardown_request
def shutdown_session(exception=None):
  db_session.remove()
