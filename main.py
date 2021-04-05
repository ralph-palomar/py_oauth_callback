from flask import Flask, request, jsonify
from waitress import serve
from paste.translogger import TransLogger
from logging.handlers import RotatingFileHandler
import logging
import os
import json
import time

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
    consumer_key = request.args.get("consumerKey")
    if consumer_key is None:
        return "Required query parameter is missing: consumerKey", 400

    oauth_headers = {
        "oauth_consumer_key": "",
        "oauth_nonce": "",
        "oauth_signature": "",
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": int(time.time()),
        "oauth_token": "",
        "oauth_version": "1.0"
    }
    oauth_header_keys = oauth_headers.keys()
    oauth_header_values = oauth_headers.values()

    try:
        return oauth_headers
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
