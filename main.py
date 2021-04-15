from flask import Flask, request, make_response
from waitress import serve
from paste.translogger import TransLogger
from config import logger
from rphelpers import create_response, create_twitter_auth_header, create_twitter_signature, log_payload, split_form_data, get_min_twitter_oauth_headers, percent_encode
import os
import requests
import config

# APP CONFIG
api = Flask(__name__)

# REQUEST PATH
base_path = '/oauth/callback'


# MAIN ENTRY POINT
if __name__ == '__main__':
    try:
        serve(TransLogger(api, logger=logger), host='0.0.0.0', port=5000, threads=16)
    except Exception as ex:
        logger.exception(ex)


# CORS CHECKPOINT
@api.route(f'{base_path}/twitter', methods=['OPTIONS'])
@api.route(f'{base_path}/twitter/authorize', methods=['OPTIONS'])
def pre_flight():
    return create_response({}), 200


@api.route(f'{base_path}/twitter', methods=['GET'])
def process_twitter():
    try:
        payload = request.json
        log_payload("REQUEST BODY", payload)

        consumer_key = os.environ['TWITTER_CONSUMER_KEY']
        consumer_secret = os.environ['TWITTER_CONSUMER_SECRET']
        access_token_url = f'https://api.twitter.com/oauth/access_token?oauth_consumer_key={consumer_key}&{request.query_string.decode()}'
        res = requests.request('POST', access_token_url)
        access_token_data = split_form_data(res.text)
        mongo_db = config.mongo_db('app', os.environ['MONGO_DB_PWD'], 'twitter')
        user_id = access_token_data['user_id']
        mongo_db['tokens'].replace_one({"user_id": user_id}, access_token_data, upsert=True)

        # TEST
        oauth_headers = get_min_twitter_oauth_headers(consumer_key)
        oauth_token = access_token_data['oauth_token']
        token_secret = access_token_data['oauth_token_secret']
        oauth_headers['oauth_token'] = oauth_token
        hmac_signature = create_twitter_signature('GET', f'https://api.twitter.com/2/users/{user_id}', consumer_secret, token_secret)
        oauth_headers['oauth_signature'] = percent_encode(hmac_signature)
        auth_header = create_twitter_auth_header(oauth_headers)

        user_details = requests.request('GET', f'https://api.twitter.com/2/users/{user_id}', headers={
            "Authorization": auth_header
        })

        return user_details.json(), user_details.status_code

    except Exception as e:
        logger.exception(e)


@api.route(f'{base_path}/twitter/authorize', methods=['GET'])
def invoke_twitter_api():
    try:
        consumer_key = os.environ['TWITTER_CONSUMER_KEY']
        consumer_secret = os.environ['TWITTER_CONSUMER_SECRET']
        callback_url = os.environ['TWITTER_CALLBACK_URL']

        # INITIAL OAUTH HEADERS
        oauth_headers = get_min_twitter_oauth_headers(consumer_key)
        oauth_headers['oauth_callback'] = callback_url

        hmac_signature = create_twitter_signature('POST', 'https://api.twitter.com/oauth/request_token', oauth_headers, consumer_secret)

        # APPEND THE HMAC SHA1 SIGNATURE TO THE HEADERS
        oauth_headers['oauth_signature'] = percent_encode(hmac_signature)

        auth_header = f'{create_twitter_auth_header(oauth_headers)}, oauth_callback="{percent_encode(oauth_headers["oauth_callback"])}"'
        logger.info(auth_header)

        res = requests.request('POST', 'https://api.twitter.com/oauth/request_token', headers={
            "Authorization": auth_header
        })

        form_data = split_form_data(res.text)
        oauth_token = form_data['oauth_token']
        oauth_callback_confirmed = form_data['oauth_callback_confirmed']
        redirect_url = 'https://www.google.com'

        if oauth_callback_confirmed == 'true':
            redirect_url = f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}'

        response = make_response()
        response.headers['Location'] = redirect_url
        return response, 302

    except Exception as e:
        logger.exception(e)
