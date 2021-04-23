from flask import Flask
from waitress import serve
from paste.translogger import TransLogger
import config
import rphelpers
import twitter

# APP CONFIG
api = Flask(__name__)

# REQUEST PATH
base_path = '/oauth/callback'


# MAIN ENTRY POINT
if __name__ == '__main__':
    try:
        serve(TransLogger(api, logger=config.logger), host='0.0.0.0', port=5000, threads=16)
    except Exception as ex:
        config.logger.exception(ex)


# CORS CHECKPOINT
@api.route(f'{base_path}/twitter', methods=['OPTIONS'])
@api.route(f'{base_path}/twitter/authorize', methods=['OPTIONS'])
@api.route(f'{base_path}/google', methods=['OPTIONS'])
@api.route(f'{base_path}/google/authorize', methods=['OPTIONS'])
def pre_flight():
    return rphelpers.create_response({}), 200


# API DEFINITIONS
@api.route(f'{base_path}/twitter', methods=['GET'])
def twitter_obtain_access_token():
    twitter.obtain_access_token()


@api.route(f'{base_path}/twitter/authorize', methods=['GET'])
def twitter_authorize():
    twitter.authorize()
