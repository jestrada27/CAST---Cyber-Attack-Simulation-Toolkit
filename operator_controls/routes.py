
from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId
from database import database_name
#from .operator import 
import time

#blueprint for route and database collection data
xss_bp = Blueprint("operator_cntrl_bp", __name__)
