from flask import make_response
import config
import os


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
    return "SUCCESS", 200
