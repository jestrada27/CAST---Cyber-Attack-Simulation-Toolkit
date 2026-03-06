from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()
connection = os.getenv('MONGODB_URI')

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)  

database_name = dbclient["CAST"]
