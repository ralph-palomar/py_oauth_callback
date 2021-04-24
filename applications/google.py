from flask import make_response, request
from utilities import rphelpers
from definitions import app_connection
import config
import os
import requests


def authorize():
    try:
        response = make_response()
        response.headers['Location'] = f'https://accounts.google.com/o/oauth2/v2/auth?' \
                                       f'client_id={os.environ["GOOGLE_CLIENT_ID"]}&' \
                                       f'redirect_uri={os.environ["GOOGLE_CALLBACK_URL"]}&' \
                                       f'response_type=code&' \
                                       f'scope=https://www.googleapis.com/auth/spreadsheets&' \
                                       f'access_type=offline'

        return response, 302

    except Exception as e:
        config.logger.exception(e)


def obtain_access_token():
    try:
        authorization_code = request.args.get("code")
        res = requests.request('POST', 'https://oauth2.googleapis.com/token', params={
            "client_id": os.environ['GOOGLE_CLIENT_ID'],
            "client_secret": os.environ['GOOGLE_CLIENT_SECRET'],
            "code": authorization_code,
            "grant_type": "authorization_code",
            "redirect_uri": os.environ['GOOGLE_CALLBACK_URL']
        }, headers={
            "Content-Type": "application/x-www-form-urlencoded"
        })

        # SAVE CREDENTIALS
        if res.status_code == 200:
            config.logger.info(res.text)
            data = res.json()
            oauth_connection = app_connection.OAuthConnection(
                connection_name="My Google connection",
                connection_type=app_connection.ConnectionType.GOOGLE,
                client_id=os.environ['GOOGLE_CLIENT_ID'],
                client_secret=os.environ['GOOGLE_CLIENT_SECRET'],
                access_token=data['access_token'],
                refresh_token=data['refresh_token']
            )
            rphelpers.save_oauth_credentials(oauth_connection)

        return "SUCCESS" if res.status_code == 200 else "FAILED", res.status_code

    except Exception as e:
        config.logger.exception(e)
