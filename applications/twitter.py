from flask import request, make_response
from utilities import rphelpers
from definitions import app_connection
import os
import requests
import config


def obtain_access_token():
    try:
        payload = request.json
        rphelpers.log_payload("REQUEST BODY", payload)

        consumer_key = os.environ['TWITTER_CONSUMER_KEY']
        consumer_secret = os.environ['TWITTER_CONSUMER_SECRET']
        access_token_url = f'https://api.twitter.com/oauth/access_token?oauth_consumer_key={consumer_key}&{request.query_string.decode()}'
        res = requests.request('POST', access_token_url)
        access_token_data = rphelpers.split_form_data(res.text)

        # TEST
        oauth_headers = rphelpers.get_min_twitter_oauth_headers(consumer_key)
        oauth_token = access_token_data['oauth_token']
        token_secret = access_token_data['oauth_token_secret']
        oauth_headers['oauth_token'] = oauth_token
        oauth_headers['user_id'] = access_token_data['user_id']
        user_details_url = f'https://api.twitter.com/1.1/users/show.json'
        hmac_signature = rphelpers.create_twitter_signature('GET', user_details_url, parameters=oauth_headers, consumer_secret=consumer_secret, token_secret=token_secret)
        oauth_headers['oauth_signature'] = rphelpers.percent_encode(hmac_signature)
        auth_header = f'{rphelpers.create_twitter_auth_header(oauth_headers)}, oauth_token="{rphelpers.percent_encode(oauth_token)}"'
        user_details = requests.request('GET', user_details_url, params={
            "user_id": access_token_data['user_id']
        }, headers={
            "Authorization": auth_header
        })

        # SAVE CREDENTIALS
        oauth_connection = app_connection.OAuthConnection(
            connection_name="My Twitter connection",
            connection_type=app_connection.ConnectionType.TWITTER,
            client_id=consumer_key,
            client_secret=consumer_secret,
            access_token=access_token_data['oauth_token'],
            access_token_secret=access_token_data['oauth_token_secret'],
            user_id=access_token_data['user_id'],
            user_name=access_token_data['screen_name']
        )
        rphelpers.save_oauth_credentials("My Twitter connection", oauth_connection)

        return "SUCCESS" if user_details.status_code == 200 else "FAILED", user_details.status_code

    except Exception as e:
        config.logger.exception(e)


def authorize():
    try:
        consumer_key = os.environ['TWITTER_CONSUMER_KEY']
        consumer_secret = os.environ['TWITTER_CONSUMER_SECRET']
        callback_url = os.environ['TWITTER_CALLBACK_URL']

        # INITIAL OAUTH HEADERS
        oauth_headers = rphelpers.get_min_twitter_oauth_headers(consumer_key)
        oauth_headers['oauth_callback'] = callback_url

        hmac_signature = rphelpers.create_twitter_signature('POST', 'https://api.twitter.com/oauth/request_token', parameters=oauth_headers, consumer_secret=consumer_secret)

        # APPEND THE HMAC SHA1 SIGNATURE TO THE HEADERS
        oauth_headers['oauth_signature'] = rphelpers.percent_encode(hmac_signature)

        auth_header = f'{rphelpers.create_twitter_auth_header(oauth_headers)}, oauth_callback="{rphelpers.percent_encode(oauth_headers["oauth_callback"])}"'

        res = requests.request('POST', 'https://api.twitter.com/oauth/request_token', headers={
            "Authorization": auth_header
        })

        form_data = rphelpers.split_form_data(res.text)
        oauth_token = form_data['oauth_token']
        oauth_callback_confirmed = form_data['oauth_callback_confirmed']
        redirect_url = 'https://www.google.com'

        if oauth_callback_confirmed == 'true':
            redirect_url = f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}'

        response = make_response()
        response.headers['Location'] = redirect_url
        return response, 302

    except Exception as e:
        config.logger.exception(e)
