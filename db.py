import pymongo
from bson.objectid import ObjectId


class MongoColl:
    def __init__(self, url, database, collection):
        self.client = pymongo.MongoClient(url)
        self.database = self.client[database]
        self.collection = self.database[collection]

    def read(self, query_dict={}, columns_dict=None, one=True):
        if one:
            document = self.collection.find_one(query_dict, columns_dict)
            if document:
                for key in document:
                        if key=="_id":
                            document[key]=str(document[key])
            return document
        else:
            documents = self.collection.find(query_dict, columns_dict)
            output = [{key:d[key] for key in d} for d in documents]
            for dic in output:
                for key in dic:
                    if key=="_id":
                        dic[key]=str(dic[key])
            return output

    def create(self, document):
        if "_id" in document.keys():
            document.pop("_id")
        x = self.collection.insert_one(document)
        return x.inserted_id

    def update(self, filter_dict, new_dict, one=True):
        if one:
            x = self.collection.update_one(filter_dict, {"$set": new_dict})
        else:
            x = self.collection.update_many(filter_dict, {"$set": new_dict})
        return x.modified_count

    def delete(self, filter_dict=None, one=True):
        if filter_dict != None:
            if one:
                x = self.collection.delete_one(filter_dict)
            else:
                x = self.collection.delete_many(filter_dict)
            return x.deleted_count
        else:
            return 0


class CardsColl(MongoColl):
    def __init__(self, url):
        MongoColl.__init__(self, url, "cards", "cards")


class UsersColl(MongoColl):
    def __init__(self, url):
        MongoColl.__init__(self, url, "cards", "users")


if __name__ == "__main__":
    m = MongoColl("mongodb://localhost:27017/", "cards", "cards")
    
