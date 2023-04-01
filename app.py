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

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

cors = CORS(app)
app.config.from_object(os.environ['APP_SETTINGS'])
db = SQLAlchemy(app)
migrate = Migrate(app, db)
MONGO_URI = os.environ.get('MONGO_URI')
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


def get_product_by_id(id):  
    return products_collection.find_one({"_id": ObjectId(id)})

def get_cached_products():
    products_list = redis_client.get("products")

    if products_list is not None:
        return json.loads(redis_client.get('products').decode('utf-8'))

    return None


def update_cached_products(id, update_data):
    cached_products = get_cached_products()
    if cached_products is None:
        return None
    for cached_product in cached_products:
        if cached_product["id"] == id:
            cached_product.update(update_data)

    redis_client.set("products", json.dumps(cached_products))

def delete_product_from_cache(id):
    cached_products = get_cached_products()
    filtered_products = [product for product in cached_products if product["id"] != id]
    redis_client.set("products", json.dumps(filtered_products))

def find_product_from_cache(attribute,value):
    cached_products = get_cached_products()
    if cached_products is None:
        return None
    for cached_product in cached_products:
        if cached_product[attribute] == value:
            return cached_product
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
            current_user = User.query\
                .filter_by(email = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        if current_user is not None:
            return  f(current_user, *args, **kwargs)
        
        return jsonify({"message": "User not found"}, 404)

    return decorated


@app.route("/current-user", methods=["GET"])
@log_request
@token_required
def current_user(current_user):
    return jsonify({"current_user": current_user.to_dict()})

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
    cached_products = get_cached_products()
    if cached_products is not None:
        return jsonify(cached_products)

    products_list = []
    mongo_products = products_collection.find()

    for item in mongo_products:
        product_dict = {
            "id": str(item['_id']),
            "name"    : str(item['name']),
            "price"   : int(item['price']),
            "in_stock_quantity": int(item['in_stock_quantity'])
        }
        products_list.append(product_dict)
        redis_client.set('products', json.dumps(products_list))

    return jsonify(products_list)


@app.route("/add-to-cart", methods=["POST"])
@log_request
@token_required
def add_to_cart(current_user):
    try:
        item = request.json['item']
        sessions_collection.update_many({'public_id': current_user.email}, 
                                        {'$addToSet': { 'items_added': item } })
        return jsonify({"message": "Item added to the cart"}, 200)
        
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/checkout", methods=["POST"])
@log_request
@token_required
def checkout(current_user):
    try:
        items = request.json["items"]
        for item in items:
            product = get_product_by_id((item["id"]))
            if int(item["quantity"]) > int(product["in_stock_quantity"]):
                orders_collection.insert_one({
                    "items": items, 
                    "public_id": current_user.email,
                    "status": "Out of Stock",
                    "order_date": datetime.now()
                })
                return jsonify({
                    "message":f"The item {item['name']} is not available in {item['quantity']} units"
                    }),404
            update_data = {
                "in_stock_quantity": int(product["in_stock_quantity"]) - int(item["quantity"])
            }
            products_collection.update_many({"_id": ObjectId(item["id"])}, 
                                            {"$set": update_data})
            
            orders_collection.insert_one({
                "items": items, 
                "public_id": current_user.email,
                "status": "Purchased",
                "order_date": datetime.now()
            })

        return jsonify({"message": "The purchase was succesfully completed"}),200
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/products", methods=["POST"])
@log_request
def add_product():
    try:
        request_data = request.json["product"]
        cached_products = get_cached_products()
        product = find_product_from_cache("name", request_data["name"])

        if product is not None:
            return jsonify({"message": "The resource already exists"}), 409
        
        result = products_collection.insert_one(request_data)
        request_data["id"] = str(result.inserted_id)
        del request_data["_id"]
        if cached_products is None:
            cached_products = [request_data]
        else:
            cached_products.append(request_data)
        redis_client.set('products', json.dumps(cached_products))
        return jsonify({"message": "Succesfully added"}), 200

    except Exception as e:
        print("the exception", e)
        return jsonify({"message" : "Something went wrong"}), 404

@app.route("/product/<id>", methods=["DELETE"])
@log_request
def delete_product(id):
    try:
        product = find_product_from_cache("id", id)
        if product is None:
            return jsonify({"message": "The item was not found"}), 404
        
        filtered_products = delete_product_from_cache(id)
        products_collection.delete_many({"_id": ObjectId(id)})
        redis_client.set("products", json.dumps(filtered_products))
        return jsonify({"message": "Succesfully removed"}), 200
    
    except Exception as e:
        print(e)
        return jsonify({"message" : "Something went wrong"}), 404
    
@app.route("/product/<id>", methods=["PUT"])
@log_request
def update_product(id):
    try:
        update_data = request.json["product"]
        product = find_product_from_cache("id", id)
        if product is None:
            return jsonify({"message": "The item was not found"}), 404
        
        products_collection.update_many({'_id': ObjectId(id)}, {'$set': update_data})
        update_cached_products(id, update_data)
        return jsonify({"message": "Succesfully updated"}), 200
        
    except Exception as e:
        print("the exception", e)
        return jsonify({"message": "Something went wrong"}), 404
    
