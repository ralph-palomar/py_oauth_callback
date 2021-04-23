from logging.handlers import RotatingFileHandler
import pymongo
import logging


def mongo_db(user, pwd, db):
    m_client = pymongo.MongoClient(username=user, password=pwd, authSource=db)
    return m_client[db]


# SETUP ROTATING LOGGERS
logger = logging.getLogger('waitress')
handler = RotatingFileHandler(filename='main.log', mode='a', maxBytes=20 * 1024 * 1024, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(funcName)s (%(lineno)d) %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)
