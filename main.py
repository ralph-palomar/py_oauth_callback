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


@api.route(f'{base_path}/twitter/actions', methods=['GET', 'POST', 'PUT'])
def invoke_twitter_api():
    try:
        consumer_key = request.args.get("consumerKey")
        consumer_secret = request.args.get("consumerSecret")
        twitter_api = request.args.get("twitterAPI")
        twitter_method = request.method
        token_secret = request.args.get("tokenSecret")

        if consumer_key is None:
            return "Required query parameter is missing: consumerKey", 400
        if consumer_secret is None:
            return "Required query parameter is missing: signingKey", 400
        if twitter_api is None:
            return "Required query parameter is missing: twitterAPI", 400
        if token_secret is None:
            return "Required query parameter is missing: tokenSecret", 400

        # INITIAL OAUTH HEADERS
        oauth_headers = {
            "oauth_consumer_key": urllib.parse.quote(consumer_key, safe=''),
            "oauth_nonce": re.sub(r'\W+', '', base64.b64encode(os.urandom(32)).decode()),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": int(time.time()),
            "oauth_version": "1.0"
        }

        # APPEND OTHER OAUTH ARGS
        for k, v in request.args.items():
            if k.startswith('oauth_'):
                oauth_headers[k] = urllib.parse.quote(v, safe='')

        # SORT BY HEADER KEY NAME
        output_string_array = []
        for k, v in sorted(oauth_headers.items()):
            output_string_array.append(f'{k}%3D{v}')

        # CREATE A SIGNATURE BASE STRING AND GENERATE HMAC SHA1 SIGNATURE
        output_string = twitter_method + '&' + urllib.parse.quote(twitter_api, safe='') + '&' + '%26'.join(output_string_array)
        log_payload("OUTPUT_SIGNATURE_STRING", output_string)
        signing_key = urllib.parse.quote(consumer_secret, safe='') + '&' + urllib.parse.quote(token_secret, safe='')
        hmac_signature = base64.b64encode(hmac.new(bytes(signing_key, 'utf-8'), bytes(output_string, 'utf-8'), sha1).digest()).decode()

        # APPEND THE HMAC SHA1 SIGNATURE TO THE HEADERS
        oauth_headers['oauth_signature'] = urllib.parse.quote(hmac_signature, safe='')

        # SORT THE HEADERS BY KEY NAME AND GENERATE THE FINAL OUTPUT
        final_output = []
        for k, v in sorted(oauth_headers.items()):
            final_output.append(f'{k}="{v}"')

        auth_header = "OAuth " + ', '.join(final_output)
        log_payload("AUTH_HEADER", auth_header)

        output = requests.request(twitter_method, twitter_api, headers={
            "Authorization": auth_header
        })

        return output.json()

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
