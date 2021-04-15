from hashlib import sha1
from config import logger
from flask import request, jsonify
import os
import urllib
import base64
import re
import time
import json
import hmac


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


def create_twitter_signature(method, url, other_params=None, consumer_secret="", token_secret=""):
    # SORT BY HEADER KEY NAME
    param_string_arr = []
    for k, v in sorted(other_params.items()):
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
