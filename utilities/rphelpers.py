from functools import wraps
from hashlib import sha1
from config import logger, mongo_db_local
from flask import request, jsonify
from definitions import app_connection
from datetime import datetime, timedelta
import os
import urllib
import base64
import re
import time
import json
import hmac
import jwt

# MY OWN HELPER FUNCTIONS
def log_payload(payload_id, payload):
    logger.info(f'{request.method} | {request.full_path} | {payload_id} >>>\n{json.dumps(payload, indent=3)}')


def create_response(response_payload):
    try:
        response = jsonify(response_payload)
        response.headers['Access-Control-Allow-Origin'] = os.environ['ALLOWED_ORIGIN']
        response.headers['Access-Control-Allow-Headers'] = os.environ['ALLOWED_HEADERS']
        response.headers['Access-Control-Allow-Methods'] = os.environ['ALLOWED_METHODS']
        response.headers['Access-Control-Max-Age'] = 3600
        return response
    except Exception as e:
        logger.exception(e)


def percent_encode(input_str):
    return urllib.parse.quote(input_str, safe='')


def split_form_data(input_str):
    output_dict = {}
    for attributes in input_str.split('&'):
        attribute = attributes.split('=')
        output_dict[attribute[0]] = attribute[1]

    return output_dict


def get_min_twitter_oauth_headers(consumer_key):
    oauth_headers = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": re.sub(r'\W+', '', base64.b64encode(os.urandom(32)).decode()),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": int(time.time()),
        "oauth_version": "1.0"
    }

    return oauth_headers


def create_twitter_signature(method, url, parameters={}, consumer_secret="", token_secret=""):
    # SORT BY HEADER KEY NAME
    param_string_arr = []
    for k, v in sorted(parameters.items()):
        param_key = f'{k}'
        param_val = f'{v}'
        param_string_arr.append(f'{percent_encode(param_key)}={percent_encode(param_val)}')

    # CREATE A SIGNATURE BASE STRING AND GENERATE HMAC SHA1 SIGNATURE
    signature_base_str = method + '&' + percent_encode(url) + '&' + percent_encode('&'.join(param_string_arr))
    signing_key = percent_encode(consumer_secret) + '&' + token_secret
    hmac_signature = base64.b64encode(
        hmac.new(bytes(signing_key, 'utf-8'), bytes(signature_base_str, 'utf-8'), sha1).digest()).decode()

    log_payload("OAUTH_SIGNATURE", {
        "signatureBaseString": signature_base_str,
        "signingKey": signing_key,
        "hmac": hmac_signature
    })

    return hmac_signature


def create_twitter_auth_header(oauth_headers):
    return f'OAuth oauth_nonce="{oauth_headers["oauth_nonce"]}", oauth_signature_method="{oauth_headers["oauth_signature_method"]}", oauth_timestamp="{oauth_headers["oauth_timestamp"]}", oauth_consumer_key="{oauth_headers["oauth_consumer_key"]}", oauth_signature="{oauth_headers["oauth_signature"]}", oauth_version="{oauth_headers["oauth_version"]}"'


def save_oauth_credentials(oauth_connection_details: app_connection.OAuthConnection):
    mongodb = mongo_db_local()
    connection_name = oauth_connection_details.connection_name
    connection_details = vars(oauth_connection_details)

    if connection_details['refresh_token'] == "":
        connection_details.pop('refresh_token')

    mongodb['app_connections'].update_one({"connection_name": connection_name}, {"$set": connection_details}, upsert=True)


# BASIC AUTHENTICATION WRAPPER
def requires_basic_authentication(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            auth = request.authorization
            if auth.username == "X-API-KEY":
                logger.info(request.host)
                claims = jwt.decode(auth.password, key=os.environ['MASTER_KEY'], issuer=request.host, algorithms=['HS256'])
                if not is_authenticated(claims['u'], claims['p']):
                    return unauthorized()
            else:
                if not auth or not is_authenticated(auth.username, auth.password):
                    return unauthorized()

            return f(*args, **kwargs)

        except Exception as e:
            logger.exception(e)
            return unauthorized()

    return wrapper


def is_authenticated(username, password):
    try:
        return username == os.environ['APP_USERNAME'] and password == os.environ['APP_PASSWORD']

    except Exception as e:
        logger.exception(e)


def unauthorized():
    return "FORBIDDEN", 401


def generate_jwt():
    try:
        token = jwt.encode({
            "u": os.environ['APP_USERNAME'],
            "p": os.environ['APP_PASSWORD'],
            "exp": datetime.utcnow() + timedelta(seconds=3),
            "iss": os.environ['DOMAIN']
        }, key=os.environ['MASTER_KEY'], algorithm='HS256')

        return create_response({"token": token}), 200

    except Exception as e:
        logger.exception(e)
