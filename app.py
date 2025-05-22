from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flasgger import Swagger
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import os
from datetime import timedelta, datetime
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
swagger = Swagger(app)
CORS(app)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')  # Change in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# MongoDB setup
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client.get_database()
users_collection = db.users

# JWT setup
jwt = JWTManager(app)

@app.route('/users', methods=['GET'])
def get_users():
    """
    Get all users
    ---
    tags:
      - Users
    responses:
      200:
        description: A list of user records
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                    example: "60d5ec49f1c2b8a0f8e4e4b0"
                  name:
                    type: string
                    example: "John Doe"
                  email:
                    type: string
                    example: "john@example.com"
    """
    users = []
    for user in users_collection.find():
        users.append({
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user.get("email", "")
        })

    return jsonify({"users": users}), 200

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: Register
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: user@example.com
            password:
              type: string
              example: mypassword
            name:
              type: string
              example: John Doe
    responses:
      201:
        description: User registered successfully
      400:
        description: Missing email or password
      409:
        description: User already exists
    """

    data = request.get_json()
    
    # Validate input
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400
    
    # Check if user already exists
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'message': 'User already exists'}), 409
    
    # Hash the password
    hashed_password = generate_password_hash(data['password'])
    
    # Create new user
    new_user = {
        'email': data['email'],
        'password': hashed_password,
        'name': data.get('name', ''),
        'created_at': datetime.utcnow()
    }
    
    # Insert user into the database
    result = users_collection.insert_one(new_user)
    
    return jsonify({'message': 'User registered successfully', 'user_id': str(result.inserted_id)}), 201

@app.route('/login', methods=['POST'])
def login():
    """
    Login with email and password, and track login location
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: credentials
        required: true
        schema:
          id: Login
          required:
            - email
            - password
            - latitude
            - longitude
          properties:
            email:
              type: string
              example: user@example.com
              description: The user’s email address
            password:
              type: string
              example: mypassword
              description: The user’s password
            latitude:
              type: number
              format: float
              example: 32.0853
              description: User’s latitude (from client-side IP lookup)
            longitude:
              type: number
              format: float
              example: 34.7818
              description: User’s longitude (from client-side IP lookup)
    responses:
      200:
        description: Login successful, returns tokens and user info
        schema:
          type: object
          properties:
            access_token:
              type: string
            refresh_token:
              type: string
            user:
              type: object
              properties:
                id:
                  type: string
                email:
                  type: string
                name:
                  type: string
      400:
        description: Missing email, password, latitude or longitude
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    if not data \
       or not data.get('email') \
       or not data.get('password') \
       or 'latitude' not in data \
       or 'longitude' not in data:
        return jsonify({'message': 'Email, password, latitude and longitude are required'}), 400

    user = users_collection.find_one({'email': data['email']})
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Save location info
    lat = float(data['latitude'])
    lng = float(data['longitude'])
    db.logins.insert_one({
        "user_id": str(user["_id"]),
        "timestamp": datetime.utcnow(),
        "latitude": lat,
        "longitude": lng
    })

    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': str(user['_id']),
            'email': user['email'],
            'name': user.get('name', '')
        }
    }), 200


@app.route('/verify', methods=['GET'])
@jwt_required()
def verify():
    """
    Verify current access token and return user info
    ---
    tags:
      - Auth
    security:
      - Bearer: []
    responses:
      200:
        description: User verified
      404:
        description: User not found
    """
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': str(user['_id']),
            'email': user['email'],
            'name': user.get('name', '')
        }
    }), 200

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    """
    Verify current access token and return user info
    ---
    tags:
      - Auth
    security:
      - Bearer: []
    responses:
      200:
        description: User verified
      404:
        description: User not found
    """
    current_user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': str(user['_id']),
            'email': user['email'],
            'name': user.get('name', '')
        }
    }), 200

@app.route('/analytics', methods=['GET'])
def get_analytics():
    """
    Get login analytics by location for the past hour
    ---
    tags:
      - Analytics
    responses:
      200:
        description: Summary of logins in the past hour by location
        schema:
          type: object
          properties:
            loginCount:
              type: integer
              example: 17
              description: Total number of logins in the last hour
            locations:
              type: array
              items:
                type: object
                properties:
                  location:
                    type: string
                    example: "Tel Aviv, Israel"
                  count:
                    type: integer
                    example: 5
    """
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    logins = list(db.logins.find({"timestamp": {"$gte": one_hour_ago}}))

    # count per unique (lat,lng) pair
    buckets = {}
    for login in logins:
        key = (login["latitude"], login["longitude"])
        buckets[key] = buckets.get(key, 0) + 1

    locations = []
    for (lat, lng), count in buckets.items():
        locations.append({
            "latitude": lat,
            "longitude": lng,
            "count": count
        })

    return jsonify({
      "loginCount": len(logins),
      "locations": locations
    }), 200


@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    Delete a user by ID
    ---
    tags:
      - Users
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: The ID of the user to delete
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: User deleted successfully
      404:
        description: User not found
        schema:
          type: object
          properties:
            message:
              type: string
              example: User not found
    """
    result = users_collection.delete_one({'_id': ObjectId(user_id)})

    if result.deleted_count == 0:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({'message': 'User deleted successfully'}), 200


@app.route('/')
def home():
    return jsonify({'message': 'Auth SDK is working!'}), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(port=port, debug=True)
