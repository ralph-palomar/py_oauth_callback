import config
import requests
import os


def authorize():
    try:
        res = requests.request('GET', 'https://accounts.google.com/o/oauth2/v2/auth', params={
            "client_id": os.environ['GOOGLE_CLIENT_ID'],
            "redirect_uri": os.environ['GOOGLE_CALLBACK_URL'],
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/spreadsheets"
        })
        config.logger.info(res.text)

    except Exception as e:
        config.logger.exception(e)
