from database import database_name
from reporting import testinsert, getReportsForUser, serialize
from bson import ObjectId
import time


collection_users = database_name['users']
# groups_collection = database_name['groups']
report_collection = database_name['reports']


users = database_name['users']
experiments = database_name['experiments'] 


# user_id = collection_users.insert_one({
#     "username": "testuser2",
#     "email": "testuser1@gmail.com",
#     "password": "testpassword"  }).inserted_id


# experiment_id = experiments.insert_one({
#     "name": "Test Experiment11",
#     "created_at": time.time()}).inserted_id

user_id = ObjectId('697e6b608e0d9e5953ddb076')
#report_id = testinsert(str(user_id), str(experiment_id)).inserted_id


reports = getReportsForUser(str(user_id))
#reports = [serialize(r) for r in reports]

print(reports)