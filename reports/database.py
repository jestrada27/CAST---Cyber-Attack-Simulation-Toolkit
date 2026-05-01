from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Connect to the cast mongodb 
load_dotenv()
connection = os.getenv('MONGODB_URI')

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)  

database_name = dbclient["CAST"]