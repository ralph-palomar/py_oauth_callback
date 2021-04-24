from flask import make_response, request
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
    authorization_code = request.get("code")
    res = requests.request('POST', 'https://oauth2.googleapis.com/token', params={
        "client_id": os.environ['GOOGLE_CLIENT_ID'],
        "client_secret": os.environ['GOOGLE_CLIENT_SECRET'],
        "code": authorization_code,
        "grant_type": "authorization_code",
        "redirect_uri": os.environ['GOOGLE_CALLBACK_URL']
    })

    return res.text, res.status_code
