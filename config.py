import pymongo


def mongo_db(user, pwd, db):
    m_client = pymongo.MongoClient('mongodb://localhost:27017/', user, pwd, db)
    return m_client[db]
