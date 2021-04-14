import pymongo


def mongo_db(user, pwd, db):
    m_client = pymongo.MongoClient(username=user, password=pwd, authSource=db)
    return m_client[db]
