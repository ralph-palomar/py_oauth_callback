import config
from config import mongo_db_local


def all_app_connections():
    try:
        mongodb = mongo_db_local()
        result = []
        for item in mongodb['app_connections'].find():
            result.append({
                "connection_name": item['connection_name'],
                "connection_type": item['connection_type']
            })

        return result, 200

    except Exception as e:
        config.logger(e)
