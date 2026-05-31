import os
import pymongo
from datetime import datetime, timezone, timedelta

client = pymongo.MongoClient('mongodb+srv://duchung04st_db_user:yBbRgRNWgfEiaFGh@cluster0.chngdtb.mongodb.net/?appName=Cluster0')
db = client['security_logs']
coll = db['requests']

cutoff = datetime.now(timezone.utc) - timedelta(days=3000)
q = {
    '$expr': {
        '$gte': [
            {'$dateFromString': {'dateString': '$timestamp', 'onError': None, 'onNull': None}},
            cutoff
        ]
    }
}

count_docs = coll.count_documents(q)
print("Count via count_documents:", count_docs)

pipeline = [
    {'$match': q},
    {'$count': 'total'}
]
res = list(coll.aggregate(pipeline))
print("Count via aggregate:", res)
