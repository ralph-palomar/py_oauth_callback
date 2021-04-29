from config import mongo_db_local


def all_app_connections():
    mongodb = mongo_db_local()
    return {}, 200
