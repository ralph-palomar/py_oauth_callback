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
@api.route(f'{base_path}/twitter/auth', methods=['OPTIONS'])
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


@api.route(f'{base_path}/twitter/auth', methods=['GET'])
def generate_twitter_auth_header():
    try:
        consumer_key = request.args.get("consumerKey")
        access_token = request.args.get("accessToken")
        signing_key = request.args.get("signingKey")

        if consumer_key is None:
            return "Required query parameter is missing: consumerKey", 400

        if signing_key is None:
            return "Required query parameter is missing: signingKey", 400

        # INITIAL OAUTH HEADERS
        oauth_headers = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": os.urandom(16).hex(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": int(time.time()),
            "oauth_version": "1.0"
        }

        # APPEND ACCESS_TOKEN IF PRESENT
        if access_token is not None:
            oauth_headers['oauth_token'] = access_token

        # SORT BY HEADER KEY NAME
        output_string_array = []
        for k, v in sorted(oauth_headers.items()):
            output_string_array.append(f'{k}={urllib.parse.quote(v, safe="")}')

        # CREATE A SIGNATURE BASE STRING AND GENERATE HMAC SHA1 SIGNATURE
        output_string = '&'.join(output_string_array)
        hmac_signature = base64.b64encode(hmac.new(bytes(signing_key,'utf-8'), bytes(output_string,'utf-8'), sha1).digest()).decode()

        # APPEND THE HMAC SHA1 SIGNATURE TO THE HEADERS
        oauth_headers['oauth_signature'] = urllib.parse.quote(hmac_signature, safe='')

        # SORT THE HEADERS BY KEY NAME AND GENERATE THE FINAL OUTPUT
        final_output = []
        for k, v in sorted(oauth_headers.items()):
            final_output.append(f'{k}={v}')

        output = f"OAuth {', '.join(final_output)}"

        return output

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
