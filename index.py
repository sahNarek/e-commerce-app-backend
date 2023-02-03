from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


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
    return list(filter(lambda d: d['id'] == id, products))[0]

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
            product = get_product_by_id(item["id"])
            if int(item["quantity"]) > product["in_stock_quantity"]:
                return jsonify({
                    "message":f"The item {item['name']} is not available in {item['quantity']} units"
                    }),404
            update_product_count(item["id"], product["in_stock_quantity"] - int(item["quantity"]))
        return jsonify({"message": "The purchase was succesfully completed"}),200
    except Exception as e:
        print(str(e))
        return jsonify({"message":"Something went wrong"}),404