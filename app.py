from flask import Flask, jsonify, request
from bson.objectid import ObjectId
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from pymongo import MongoClient
import jwt
from functools import wraps
from datetime import datetime
from flask_caching import Cache
import redis
import json
import time
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

cors = CORS(app)
app.config.from_object(os.environ['APP_SETTINGS'])
db = SQLAlchemy(app)
migrate = Migrate(app, db)
MONGO_URI = os.environ.get('MONGO_URI')
PRODUCTS_API_URL = os.environ.get("PRODUCTS_API_URL")
cluster = MongoClient(MONGO_URI)
cache = Cache(app, config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': 'redis://localhost:6379/0'})
redis_client = redis.Redis(host='localhost', port=6379, db=0)

mongo_db = cluster['e-commerece-app-db']
products_collection = mongo_db.products
orders_collection = mongo_db.orders
sessions_collection = mongo_db.sessions
requests_collection = mongo_db.requests
logs_collection = mongo_db.server_logs

from models import User

def get_current_user_from_cache():
    
    current_user = redis_client.get("current_user")

    if current_user is not None:
        print("Cache hit for users")
        return json.loads(redis_client.get('current_user').decode('utf-8'))

    return None

def log_request(f):
    @wraps(f)
    def loger(*args, **kwargs):
        current_port = request.environ.get('SERVER_PORT')
        instance = requests_collection.find_one({'port': current_port})
        if instance:
            instance_id = str(instance["_id"])
        else:
            instance = requests_collection.insert_one({"port": current_port})
            instance_id = instance.inserted_id
        
        logs_collection.insert_one({"server_id": instance_id, "method": request.method, "endpoint": request.endpoint})
        print(f"The server {instance_id} on port {current_port} received a request")

        return f(*args, **kwargs)
    
    return loger

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=['HS256'])
            expiration_time = data.get('exp')
            current_user_from_cache = get_current_user_from_cache()
            current_time = int(time.time())
            ttl = expiration_time - current_time
            if current_user_from_cache is None:
                print("Cache miss for users")
                current_user_from_db = User.query\
                    .filter_by(email = data['public_id'])\
                    .first()
                
                if current_user_from_db is None:
                    return jsonify({"message": "User not found"}, 404)

                current_user = current_user_from_db.to_dict()
            else:
                current_user = current_user_from_cache
            redis_client.set("current_user",json.dumps(current_user))
            redis_client.rpush('cache_queue', json.dumps(current_user))
            redis_client.expire('current_user', ttl)

            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        
    return decorated


@app.route("/current-user", methods=["GET"])
@log_request
@token_required
def current_user(current_user):
    return jsonify({"current_user": current_user})

@app.route("/sign-up", methods=["POST"])
def signup():
    try:
        data = request.json
        new_user = User(name=data['name'], 
                        email=data['email'], 
                        password=generate_password_hash(data['password']),
                        is_admin=False
                        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message":"Succesfully Added"})
    except SQLAlchemyError as e:
        return jsonify({"message": "Validation failed"}), 403
    
@app.route('/sign-in', methods =['POST'])
@log_request
def login():
    auth = request.json
  
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({"message": "Verification Failed"}), 401
  
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()
  
    if not user:
        return jsonify({"message": "User does not exist"}), 401
    
    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({
            'public_id': user.email,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])

        user_session = sessions_collection.find_one({"public_id": user.email})
        if not user_session:
            sessions_collection.insert_one({
                "public_id": user.email,
                "last_login": datetime.now(),
                "items_added": []
            })
        else:
            update_data = {
                "last_login": datetime.now()
            }
            sessions_collection.update_many({'public_id': user.email}, {'$set': update_data})
  
        return jsonify({'token' : token, 'user': user.to_dict()}), 201
    return jsonify({'message': "Wrong password"}), 400


@app.route("/products", methods=["GET"])
@log_request
def get_products():
    try:

        response = requests.get(f"{PRODUCTS_API_URL}/products")
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/add-to-cart", methods=["POST"])
@log_request
@token_required
def add_to_cart(current_user):
    try:
        response = requests.post(f"{PRODUCTS_API_URL}/add-to-cart", json={"current_user": current_user, "item": request.json["item"]})
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/checkout", methods=["POST"])
@log_request
@token_required
def checkout(current_user):
    try:
        response = requests.post(f"{PRODUCTS_API_URL}/checkout", json={"current_user": current_user, "items": request.json["items"]})
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404
    
@app.route("/products", methods=["POST"])
@log_request
def add_product():
    try:
        response = requests.post(f"{PRODUCTS_API_URL}/products", json={"product": request.json["product"]})
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/product/<id>", methods=["DELETE"])
@log_request
def delete_product(id):
    try:
        response = requests.delete(f"{PRODUCTS_API_URL}/product/{id}")
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/product/<id>", methods=["PUT"])
@log_request
def update_product(id):
    try:
        response = requests.put(f"{PRODUCTS_API_URL}/product/{id}", json={"product": request.json["product"]})
        return jsonify(response.json())
    
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404
