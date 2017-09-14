from pymongo import MongoClient

class Database:
    def __init__(self, db_name):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client[db_name]

    def createCollection(self, collection_name):
        self.db.create_collection(collection_name)

    def addData(self, collection_name, data):
        if collection_name not in self.db.collection_names():
            self.createCollection(collection_name)
        try:
            op = self.db[collection_name].insert_one(data)
        except:
            print('Ups, Something happened!')
        else:
            return op.inserted_id

    def deleteAll(self, collection_name):
        return self.db[collection_name].delete_many({})