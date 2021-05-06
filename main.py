from flask import Flask
from waitress import serve
from paste.translogger import TransLogger
from utilities import rphelpers, app_connection
from applications import twitter, google
import config

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
@api.route(f'{base_path}/apps', methods=['OPTIONS'])
def pre_flight():
    return rphelpers.create_response({}), 200


# API DEFINITIONS
@api.route(f'{base_path}/twitter', methods=['GET'])
def twitter_obtain_access_token():
    return twitter.obtain_access_token()


@api.route(f'{base_path}/twitter/authorize', methods=['GET'])
def twitter_authorize():
    return twitter.authorize()


@api.route(f'{base_path}/google/authorize', methods=['GET'])
def google_authorize():
    return google.authorize()


@api.route(f'{base_path}/google', methods=['GET'])
@rphelpers.requires_basic_authentication
def google_obtain_access_token():
    return google.obtain_access_token()


@api.route(f'{base_path}/apps', methods=['GET'])
@rphelpers.requires_basic_authentication
def app_connections():
    return app_connection.all_app_connections()


@api.route(f'{base_path}/token', methods=['GET'])
def acquire_token():
    return rphelpers.generate_jwt()
