from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from forms import RegisterForm, LoginForm  # Your forms.py 
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key" 
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///nerbeedb.db"  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)
CORS(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ... (your existing `load_user` function) ...
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    # ... (You might add more user fields here) ...




class Vendor(db.Model):
    __tablename__ = "vendors"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    location = db.Column(db.String(255))
    # ... (You might add more vendor fields here) ...

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendors.id"), nullable=False)
    vendor = relationship("Vendor", backref="products")
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    images = db.Column(db.JSON, nullable=False)
    category = db.Column(db.String(50), nullable=False) 
    # ... (You might add more product fields here) ...

class Chat(db.Model):
    __tablename__ = "chats"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendors.id"), nullable=False)
    user = relationship("User", backref="chats")
    vendor = relationship("Vendor", backref="chats")
    # ... (You might add more chat fields here) ...

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chats.id"), nullable=False)
    chat = relationship("Chat", backref="messages")
    sender_id = db.Column(db.Integer, nullable=False) # User ID or Vendor ID
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) 

    def to_dict(self):
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "sender_id": self.sender_id,
            "text": self.text,
            "timestamp": self.timestamp.isoformat()  # Format timestamp as ISO 8601 string
        }

# Create all the tables if they don't exist 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

# ... (your existing routes for registration, login, logout) ...
@app.route('/register', methods=["POST"])
def register():
    data = request.get_json()
    # extract the data
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 409  # Conflict


    hash_and_salted_password = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=8
    )
    new_user = User(
        email=email,
        username=username,
        password=hash_and_salted_password,
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return jsonify({"message": "Login successful!"}), 200


@app.route('/login', methods=["POST"])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password. Please try again."}), 401 
    else:
        login_user(user) 
        return jsonify({"message": "Login successful!"}), 200

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# Products API Endpoints
@app.route('/api/products')
def get_products():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

@app.route('/api/products/<int:product_id>')
def get_product(product_id):
    product = Product.query.get(product_id)
    if product:
        return jsonify(product.to_dict())
    else:
        return jsonify({"error": "Product not found"}), 404

# ... (Your existing code for admin-only routes) ...

# Chat API Endpoints
@app.route('/api/chats', methods=['POST'])
@login_required
def create_chat():
    # ... (Get user_id and vendor_id from the request) ...
    new_chat = Chat(user_id=user_id, vendor_id=vendor_id)
    db.session.add(new_chat)
    db.session.commit()
    return jsonify({"chat_id": new_chat.id}), 201

@app.route('/api/chats/<int:chat_id>/messages', methods=['GET'])
@login_required
def get_messages(chat_id):
    messages = Message.query.filter_by(chat_id=chat_id).all()
    return jsonify([message.to_dict() for message in messages])

@app.route('/api/chats/<int:chat_id>/messages', methods=['POST'])
@login_required
def send_message(chat_id):
    # ... (Get message text and sender_id from the request) ...
    new_message = Message(chat_id=chat_id, sender_id=sender_id, text=text)
    db.session.add(new_message)
    db.session.commit()
    return jsonify({"message_id": new_message.id}), 201


if __name__ == "__main__":
    app.run(debug=True)