from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
cors = CORS(app)

# TODO, add postgresql db, change folder structure, apply MVC, dependency injection
# TODO, validation and 

products = [
    {
        "id": 1,
        "name": "Nissan Tiida",
        "price": 7000,
        "in_stock_quantity": 2 
    },
    {
        "id": 2,
        "name": "Toyota Camry",
        "price": 9000,
        "in_stock_quantity": 4
    },
    {
        "id":3,
        "name": "Mazda 6",
        "price": 8000,
        "in_stock_quantity": 1
    }
]

def get_product_by_id(id):
    product = list(filter(lambda d: d['id'] == id, products))
    if len(product) >= 1:
        return product[0]
    return None

def update_product_count(id,new_count):
    for product in products:
        if product["id"] == id:
            product.update({"in_stock_quantity":new_count})

@app.route("/products", methods=["GET"])
def get_products():
    return jsonify(products)

@app.route("/checkout", methods=["POST"])
def checkout():
    try:
        items = request.json["items"]
        for item in items:
            product = get_product_by_id(int(item["id"]))
            if int(item["quantity"]) > int(product["in_stock_quantity"]):
                return jsonify({
                    "message":f"The item {item['name']} is not available in {item['quantity']} units"
                    }),404
            update_product_count(int(item["id"]), int(product["in_stock_quantity"]) - int(item["quantity"]))
        return jsonify({"message": "The purchase was succesfully completed"}),200
    except Exception as e:
        return jsonify({"message":"Something went wrong"}),404

@app.route("/products", methods=["POST"])
def add_product():
    try:
        product = request.json["product"]
        if product["name"] in list(map(lambda d: d["name"], products)):
            return jsonify({"message": "The resource already exists"}), 409
        else:
            if len(products) >= 1:
                max_id = max(list(map(lambda d: d["id"],products)))
                product["id"] = int(max_id) + 1
                products.append(product)
            product["id"] = 1
            products.append(product)
            return jsonify({"message": "Succesfully added"}), 200
    except Exception as e:
        return jsonify({"message" : "Something went wrong"}), 404

@app.route("/product/<id>", methods=["DELETE"])
def delete_product(id):
    try:
        product = get_product_by_id(int(id))
        if (product is not None):
            global products
            products = list(filter(lambda d: d["id"] != int(id), products))
            return jsonify({"message": "Succesfully removed"}), 200
        return jsonify({"message": "The item was not found"}), 404
    except Exception as e:
        return jsonify({"message" : "Something went wrong"}), 404
    
@app.route("/product/<id>", methods=["PUT"])
def update_product(id):
    try:
        product_id = int(id)
        update_data = request.json["product"]
        product = get_product_by_id(product_id)
        if (product is not None):
            global products
            # products = list(map(lambda d: d.update(update_data), products))
            for product in products:
                if product["id"] == product_id:
                    product.update(update_data)
                    
            return jsonify({"message": "Succesfully updated"}), 200
        return jsonify({"message": "The item was not found"}), 404
    except Exception as e:
        return jsonify({"message": "Something went wrong"}), 404