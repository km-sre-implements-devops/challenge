from datetime import datetime, timedelta
import logging
from functools import wraps
from flask import jsonify, request, make_response
from werkzeug.security import check_password_hash
from requests import get
import jwt

from app.models.models import Users, Whitelist
from app import app, db

logging.root.setLevel(logging.INFO)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorator


def request_ip_list(param):
    """ Request a la url con una lista de ips tor

    :param variable param: Indica blacklist completa o filtrada con whitelist.
    :type param: String

    :raises <error_type>: <error_description>
    <other exceptions>

    :rtype: List
    :return: Retorna una lista de ips filtrada o completa.
    """
    try:
        r = get('https://check.torproject.org/torbulkexitlist')
        # Lista con bloqueo de request de 30min https://www.dan.me.uk/torlist/
        if r.status_code == 403:
            return {
                "error":
                'You have already requested this api in the last 30 minutes'
            }, 403
        elif r.status_code == 200:
            if param == "dirty":
                json_response = {"blacklist": r.text.split()}
                return json_response
            elif param == "clean":
                return r.text.split()

        else:
            logging.error('########## Error 500 from blacklist url')
            return {"error": 'Something went wrong'}, 500

    except Exception as err:
        logging.exception(
            '########## Error trying to get all ip fron blacklist url')
        return str(err)


@app.route("/")
def index():
    return "Welcome to MELI Shield!"


# Login con usuario y contraseña, devuelve un token unico para inicar session
@app.route('/shield/login', methods=['POST'])
def get_login():
    auth = request.authorization
    if auth:
        user = Users.query.filter_by(username=auth.username).first()
    else:
        return make_response(
            'no user or password', 401,
            {'WWW.Authentication': 'Basic realm: "login required"'})

    if user:
        if not auth or not auth.username or not auth.password:
            return make_response(
                'could not verify', 401,
                {'WWW.Authentication': 'Basic realm: "login required"'})

        if check_password_hash(user.password, auth.password):
            token = jwt.encode(
                {
                    'id': user.id,
                    'exp': datetime.utcnow() + timedelta(minutes=30)
                }, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        logging.error('########## Error password wrong')
        return make_response(
            'password wrong', 401,
            {'WWW.Authentication': 'Basic realm: "login required"'})
    else:
        logging.error('########## Error user not found')
        return make_response(
            'user not found', 401,
            {'WWW.Authentication': 'Basic realm: "login required"'})


# Agrega ip a whitelist en la base de datos, tambien puede manejar listas
@app.route('/shield/in/whitelist', methods=['POST'])
@token_required
def add_ip_whitelist(ip):
    data = request.get_json()
    num = len(data['ip'])
    count_exists = 0
    try:
        if isinstance(data['ip'], list):
            already_exists = []
            for ip in data['ip']:
                if not Whitelist.query.filter_by(ip=ip).first():
                    list_of_ip = Whitelist(ip=ip)
                    db.session.add(list_of_ip)
                    db.session.commit()

                else:
                    already_exists.append(ip)
                    count_exists = count_exists + 1
            if count_exists == num:
                logging.warning(
                    '########## IPs: {} already exists in whitelist'.format(
                        data['ip']))
                return {
                    'error':
                    'IPs: {} already exists in whitelist'.format(data['ip'])
                }, 409
        else:
            if not Whitelist.query.filter_by(ip=data['ip']).first():
                list_of_ip = Whitelist(ip=data['ip'])
                db.session.add(list_of_ip)
                db.session.commit()
            else:
                logging.warning(
                    '########## IP: {} already exists in whitelist'.format(
                        data['ip']))
                return {
                    'error':
                    'IP: {} already exists in whitelist'.format(data['ip'])
                }, 409

    except Exception as err:
        logging.exception(
            '########## Error adding ip {} to whitelist, Exception: {}'.format(
                data['ip'], err))
        return {"error": 'Something went wrong'}, 500
    if already_exists:
        return jsonify({
            'message':
            'success={}, already_exists={}'.format(num - count_exists,
                                                   len(already_exists))
        }), 200
    else:
        return jsonify({'message': 'success'}), 200


# Devuelve todas las ip de la blacklist sin inclur las que estan en whitelist
@app.route('/shield/out/blacklist', methods=['POST'])
@token_required
def get_all_blacklist(*args):

    blacklist_json = request_ip_list("dirty")
    return blacklist_json


# Entrega toda la blacklist sin las que estan en la whitelist
@app.route('/shield/out/blacklist_cleaned', methods=['POST'])
@token_required
def get_all_blacklist_cleaned(*args):

    try:

        blacklist_array = request_ip_list("clean")
        [
            blacklist_array.remove(i) for i in
            [addr for addr in {addr.ip
                               for addr in Whitelist.query.all()}]
            if i in blacklist_array
        ]

    except Exception as err:
        logging.exception('########## Error fetching data')
        return str(err)

    json_response = {"blacklist_cleaned": blacklist_array}
    return json_response


@app.route('/shield/info/', methods=['GET'])
@token_required
def get_info():
    response = {'message': 'success'}
    return jsonify(response)


# Healthcheck endpoint
@app.route('/shield/healthcheck', methods=['GET', 'POST'])
def healthcheck():
    response = {'shield': 'ok'}
    return jsonify(response)
