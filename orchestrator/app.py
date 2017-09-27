#coding=utf-8

import sys

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
    master_config = client.run('config.values', client="wheel")['data']['return']
    if not master_config.get('templates'):
        master_config['templates'] = {}
    return render_template("templates.html", templates=master_config['templates'])

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
    form = NewTemplateForm()
    if form.validate_on_submit():
        master_config = client.run('config.values', client="wheel")['data']['return']

        BLACKLIST_ARGS = ('csrf_token', 'tgt', 'fun', 'expr_form', 'name', 'description','owner')
        args = get_filtered_post_arguments(BLACKLIST_ARGS)

        templates = master_config.get('templates', {})
        #print templates
        templates[form.name.data.strip()] = {
            'description': form.description.data.strip(),
            'fun': form.fun.data.strip(),
            'tgt': form.tgt.data.strip(),
            'expr_form': form.expr_form.data.strip(),
            'args': args}

        client.run('config.apply', client="wheel", key="templates", value=templates)

        master_config = client.run('config.values', client="wheel")

        flash('Template {0} has been successfully saved'.format(form.name.data.strip()))

        return redirect(url_for('templates'))
    return render_template("add_template.html", form=form)


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

class RunForm(Form):
    expr_form = SelectField('matcher', choices=matchers)
    tgt = StringField('target', validators=[DataRequired()])
    fun = StringField('function', validators=[DataRequired()])
    arg= StringField('arg', validators=None)

class ProbeForm(Form):
    owner = StringField('owner', validators=[DataRequired()])#32字符
    test_name = StringField('test-name', validators = [DataRequired])#32字符
    probe_type = SelectField('probe-type', choices=matchers)#0-6
    data_size = StringField('data-size', validators=[DataRequired])#0-65507
    data_fill = StringField('datafill', validators=[DataRequired])#1-800h 16进制 和data-size要都有或都没有
    destination_port = StringField('destination-port', validators=[DataRequired])#7 或 49160-65535
    dscp_code_point = StringField('dscp-code-point', validators=[DataRequired])#6bits
    hardware_time = SelectField('hardware-timestamp', choices=matchers)#yes or no
    history_size = StringField('history-size',validators=[DataRequired])#0-255
    moving_average_size = StringField('moving-average-size', validators=[DataRequired])#0-255
    probe_count = StringField('probe-count', validators=[DataRequired])#1-15
    probe_interval = StringField('probe-interval', validators=[DataRequired])#1-255
    source_address = StringField('source_address', validators=[DataRequired])#接口地址
    target = StringField('target', validators=[DataRequired])#http必须要有，或者用ip
    test_interval = StringField('test-interval', validators=[DataRequired])#0-86400

class VPNForm(Form):
    name = StringField('name', validators=[DataRequired])#必填
    network_segment = StringField('network-segment', validators=[DataRequired])#必填
    dh_group = SelectField('dh-group',choices=matchers)
    authentication_algorithm = SelectField('authentication-algorithm',choices=matchers)
    encryption_algorithm = SelectField('encryption-algorithm',choices=matchers)
    pre_shared_key = SelectField('pre-shared-key',validators=matchers)
    ipsec_protocol = SelectField('ipsec-protocol',choices=matchers)

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


@app.route("/templates/probe/new_http_get", methods = ['GET' , 'POST'])
@login_required
def add_http_get_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type',
       'dscp-code-point','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_http_metadata_get", methods = ['GET' , 'POST'])
@login_required
def add_http_metadat_get_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type',
       'dscp-code-point','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_icmp_ping", methods = ['GET' , 'POST'])
@login_required
def add_icmp_ping_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type','data-fill','data-size',
       'dscp-code-point','hardware-timestamp','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'data-fill':form.data_fill.data.strip(),
           'data-size':form.data_size.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'hardware-timestamp':form.hardware_time.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_icmp_ping_timestamp", methods = ['GET' , 'POST'])
@login_required
def add_icmp_ping_timestamp_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type','data-fill','data-size',
       'dscp-code-point','hardware-timestamp','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'data-fill':form.data_fill.data.strip(),
           'data-size':form.data_size.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'hardware-timestamp':form.hardware_time.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_tcp_ping", methods = ['GET' , 'POST'])
@login_required
def add_tcp_ping_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type','destination-port',
       'dscp-code-point','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'destination-port':form.destination_port.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_udp_ping", methods = ['GET' , 'POST'])
@login_required
def add_udp_ping_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type','destination-port',
       'dscp-code-point','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'destination-port':form.destination_port.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/probe/new_udp_ping_timestamp", methods = ['GET' , 'POST'])
@login_required
def add_udp_ping_timestamp_template():
    form = ProbeForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('owner','test-name','probe-type','destination-port',
       'dscp-code-point','history-size','moving-average-size','probe-count',
       'probe-interval','source-address','target','test-interval')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'owner':form.owner.data.strip(),
           'test-name':form.test_name.data.strip(),
           'probe-type':form.probe_type.data.strip(),
           'destination-port':form.destination_port.data.strip(),
           'dscp-code-point':form.dscp_code_point.data.strip(),
           'history-size':form.history_size.data.strip(),
           'moving-average-size':form.moving_average_size.data.strip(),
           'probe-count':form.probe_count.data.strip(),
           'probe-interval':form.probe_interval.data.strip(),
           'source-address':form.source_address.data.strip(),
           'target':form.target.data.strip(),
           'test-interval':form.test_interval.data.strip()
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_probe_template.html",form = form)

@app.route("/templates/VPn/new_vpn_static", methods = ['GET' , 'POST'])
@login_required
def add_Vpn_static_template():
    form = VPNForm()
    if form.validate_on_submit():
       master_config = client.run('config.values' , client = "wheel")['data']['return']

       BLACKLIST_ARGS = ('name','network-segment','dh-group','authentication-algorithm',
       'encryption-algorithm','pre-shared-key','ipsec-protocol')
       args = get_filtered_post_arguments(BLACKLIST_ARGS)

       templates = master_config.get('templates', {})
    #    print templates
       templates[form.owner.data.strip()] = {
           'name':form.name.data.strip(),
           'network-segment':form.network_segment.data.strip(),
           'dh-groupe':form.dh_group.data.strip(),
           'authentication-algorithm':form.authentication_algorithm.data.strip(),
           'encryption-algorithm':form.encryption_algorithm.data.strip(),
           'pre-shared-key':form.pre_shared_key.data.strip(),
           'ipsec-protocol':form.ipsec_protocol.data.strip(),
           
       }
       client.run('config.apply', client="wheel",key="templates",value=templates)

       master_config = client.run('config.values', client = "wheel")

       flash('Template {0} has been successfully saved'.format(form.owner.data.strip()))

       return redirect(url_for('templates'))
    return render_template("add_VPN_template.html",form = form)

