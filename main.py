from flask import Flask, request, jsonify
from waitress import serve
from paste.translogger import TransLogger
from logging.handlers import RotatingFileHandler
from hashlib import sha1
import logging
import os
import json
import time
import urllib
import hmac
import base64
import re
import requests

# APP CONFIG
api = Flask(__name__)

# REQUEST PATH
base_path = '/oauth/callback'

# SETUP ROTATING LOGGERS
logger = logging.getLogger('waitress')
handler = RotatingFileHandler(filename=f'{__name__}.log', mode='a', maxBytes=20 * 1024 * 1024, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(funcName)s (%(lineno)d) %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# MAIN ENTRY POINT
if __name__ == '__main__':
    try:
        serve(TransLogger(api, logger=logger), host='0.0.0.0', port=5000, threads=16)
    except Exception as ex:
        logger.exception(ex)


# CORS CHECKPOINT
@api.route(f'{base_path}/twitter', methods=['OPTIONS'])
@api.route(f'{base_path}/twitter/request_token', methods=['OPTIONS'])
def pre_flight():
    return create_response({}), 200


@api.route(f'{base_path}/twitter', methods=['GET'])
def process_twitter():
    try:
        payload = request.json
        log_payload("REQUEST BODY", payload)

        # APPLICATION LOGIC HERE #

        return create_response({
            "status": "success"
        }), 200

    except Exception as e:
        logger.exception(e)


@api.route(f'{base_path}/twitter/request_token', methods=['POST'])
def invoke_twitter_api():
    try:
        consumer_key = request.args.get("consumerKey")
        consumer_secret = request.args.get("consumerSecret")
        access_token = request.args.get("accessToken")
        token_secret = request.args.get("tokenSecret")

        if consumer_key is None:
            return "Required query parameter is missing: consumerKey", 400
        if consumer_secret is None:
            return "Required query parameter is missing: signingKey", 400
        if access_token is None:
            return "Required query parameter is missing: accessToken", 400
        if token_secret is None:
            return "Required query parameter is missing: tokenSecret", 400

        # INITIAL OAUTH HEADERS
        oauth_headers = {
            "oauth_callback": "https://www.tes8.link/oauth/callback/twitter",
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": re.sub(r'\W+', '', base64.b64encode(os.urandom(32)).decode()),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": int(time.time()),
            "oauth_version": "1.0"
        }

        # SORT BY HEADER KEY NAME
        param_string_arr = []
        for k, v in sorted(oauth_headers.items()):
            param_key = f'{k}'
            param_val = f'{v}'
            param_string_arr.append(f'{percent_encode(param_key)}={percent_encode(param_val)}')

        # CREATE A SIGNATURE BASE STRING AND GENERATE HMAC SHA1 SIGNATURE
        signature_base_str = 'POST' + '&' + percent_encode('https://api.twitter.com/oauth/request_token') + '&' + percent_encode('&'.join(param_string_arr))
        signing_key = percent_encode(consumer_secret) + '&'
        hmac_signature = base64.b64encode(hmac.new(bytes(signing_key, 'utf-8'), bytes(signature_base_str, 'utf-8'), sha1).digest()).decode()

        log_payload("OAUTH_SIGNATURE", {
            "signatureBaseString": signature_base_str,
            "signingKey": signing_key,
            "hmac": hmac_signature
        })

        # APPEND THE HMAC SHA1 SIGNATURE TO THE HEADERS
        oauth_headers['oauth_signature'] = percent_encode(hmac_signature)

        auth_header = f'OAuth oauth_nonce="{oauth_headers["oauth_nonce"]}", oauth_callback="{percent_encode(oauth_headers["oauth_callback"])}", oauth_signature_method="{oauth_headers["oauth_signature_method"]}", oauth_timestamp="{oauth_headers["oauth_timestamp"]}", oauth_consumer_key="{oauth_headers["oauth_consumer_key"]}", oauth_signature="{oauth_headers["oauth_signature"]}", oauth_version="{oauth_headers["oauth_version"]}"'
        logger.info(auth_header)

        res = requests.request('POST', 'https://api.twitter.com/oauth/request_token', headers={
            "Authorization": auth_header
        })

        logger.info(res.json())
        return res.json(), res.status_code

    except Exception as e:
        logger.exception(e)


# HELPER FUNCTIONS
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
