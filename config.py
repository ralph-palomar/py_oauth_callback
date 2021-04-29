from logging.handlers import RotatingFileHandler
import pymongo
import logging
import os


def mongo_db_local(user=os.environ['MONGO_DB_USR'], pwd=os.environ['MONGO_DB_PWD'], db=os.environ['MONGO_DB_']):
    m_client = pymongo.MongoClient(username=user, password=pwd, authSource=db)
    return m_client[db]


# SETUP ROTATING LOGGERS
logger = logging.getLogger('waitress')
handler = RotatingFileHandler(filename='main.log', mode='a', maxBytes=20 * 1024 * 1024, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(funcName)s (%(lineno)d) %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)
