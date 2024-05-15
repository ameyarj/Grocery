from flask import Flask, jsonify, request, session,Response,current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from sqlalchemy.orm import relationship
from flask_jwt_extended import JWTManager, create_access_token,get_jwt_identity,jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_principal import Principal, RoleNeed, Permission, UserNeed, identity_loaded
from flask_jwt_extended import jwt_required,get_jwt_identity
from flask_login import current_user
from datetime import datetime
from werkzeug.utils import secure_filename
# from flask_caching import Cache
from io import StringIO
import csv
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'bello'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', 'json', 'query_string']
app.config['JWT_COOKIE_SECURE'] = False
app.config['PRINCIPALS_USE_POLICY'] = True
app.secret_key = 'bellothehello'

CORS(app, resources={r'/*': {'origins': '*'}})
# cache = Cache(app, config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': 'redis://localhost:6379/0'})

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
principal = Principal(app)


store_manager_role = RoleNeed('store_manager')
admin_permission = Permission(RoleNeed('admin'))


@principal.identity_loader
def load_identity():
    if 'current_user' in session:
        return session['current_user']

@principal.identity_saver
def save_identity(identity, **kwargs):
    session['current_user'] = identity

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user

    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role))  


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    carts = db.relationship('Cart', backref='user', lazy=True)
    feedbacks = relationship('Feedback', back_populates='user')


class StoreManager(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), default="pending")  
    role = db.Column(db.String(20), default='store_manager')
    messages_sent = db.relationship('Message', backref='sender', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('store_manager.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False, default=1)

    recipient = relationship('Admin', foreign_keys=[recipient_id], backref='received_messages')

    is_read = db.Column(db.Boolean, default=False)    

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='admin')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    image_filename = db.Column(db.String(255))
    products = db.relationship('Product', back_populates='category')

    def __init__(self, title, description, image_filename=None):
        self.title = title
        self.description = description
        self.image_filename = image_filename

class CategoryRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    image_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    store_manager_id = db.Column(db.Integer, db.ForeignKey('store_manager.id'))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Float)
    image_filename = db.Column(db.String(255))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', back_populates='products')

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    product_name = db.Column(db.String, nullable=False)
    product_image = db.Column(db.String, nullable=False)
    product_price = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class PurchaseHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    product_name = db.Column(db.String(255), nullable=False)
    product_image = db.Column(db.String(255), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username, product_id, product_name, product_image, product_price, quantity):
        self.username = username
        self.product_id = product_id
        self.product_name = product_name
        self.product_image = product_image
        self.product_price = product_price
        self.quantity = quantity
        self.purchase_date = datetime.utcnow()
    def __repr__(self):
        return f'<PurchaseHistory {self.id}>'

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(100))
    bio = db.Column(db.Text)
    rating = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = relationship('User', back_populates='feedbacks')

def create_tables():
    db.create_all()
@app.route('/user/signup', methods=['POST'])
def user_signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify(error='Missing username, password, email'), 400
    user = User.query.filter_by(username=username).first()

    if user:
        return jsonify(error='Username already exists'), 409
    hashed_password = generate_password_hash(password)

    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message='User signup successful'), 201

@app.route('/user/details', methods=['GET'])
@jwt_required()
def get_user_details():
    current_user = get_jwt_identity()
    username = current_user['username']

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(error='User not found'), 404

    user_details = {
        'username': user.username,
        'email': user.email,
        'password': user.password,
    }

    return jsonify(user_details), 200

@app.route('/user/edit', methods=['PUT'])
@jwt_required()
def edit_user_details():
    current_user = get_jwt_identity()
    username = current_user['username']

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(error='User not found'), 404

    data = request.json
    new_username = data.get('new_username')
    new_email = data.get('new_email')
    new_password = data.get('new_password')

    if new_username:
        user.username = new_username

    if new_email:
        user.email = new_email

    if new_password:
        hashed_password = generate_password_hash(new_password)
        user.password = hashed_password

    db.session.commit()
    new_token = create_access_token(identity={'username': new_username, 'email': new_email, 'password': new_password})

    return jsonify(message='User details updated successfully', token=new_token), 200
 

@app.route('/user/login', methods=['POST'])
def user_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify(error='Missing email or password'), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify(error='Invalid email or password'), 401

    access_token = create_access_token(identity={'id': user.id, 'email': user.email, 'username': user.username, 'role': None})
    return jsonify(access_token=access_token)

@app.route('/submit_feedback', methods=['POST'])
@jwt_required()
def submit_feedback():
    current_user = get_jwt_identity()
    user_id = current_user.get("id")
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    title = data.get('title')
    subtitle = data.get('subtitle')
    bio = data.get('bio')
    rating = data.get('rating')

    if not title or not rating:
        return jsonify({'message': 'Title and Rating are required'}), 400

    feedback = Feedback(title=title, subtitle=subtitle, bio=bio, rating=rating, user=user)
    db.session.add(feedback)
    db.session.commit()

    return jsonify({'message': 'Feedback submitted successfully'}), 200

@app.route('/get_feedback', methods=['GET'])           
def get_feedback():
    feedback_list = Feedback.query.all()

    if not feedback_list:
        return jsonify({'message': 'No feedback available'}), 404

    feedback_data = []
    for feedback in feedback_list:
        feedback_data.append({
            'id': feedback.id,
            'title': feedback.title,
            'subtitle': feedback.subtitle,
            'bio': feedback.bio,
            'rating': feedback.rating,
            'user_id': feedback.user_id
        })

    return jsonify({'feedback': feedback_data}), 200


@app.route('/store-manager/signup', methods=['POST'])
def store_manager_signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password or not email:
        return jsonify(error='Missing username, password, email'), 400
    
    store_manager = StoreManager.query.filter_by(email=email).first()
    
    if store_manager:
        return jsonify(error='Store Manager Already Exists!'), 409
    
    store_manager = StoreManager(username=username, password=generate_password_hash(password), email=email, role='store_manager')  
    db.session.add(store_manager)
    db.session.commit()
    
    return jsonify(message='Store Manager signup successful'), 201


@app.route('/store-manager/login', methods=['POST'])
def store_manager_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify(error='Missing email or password'), 400
    
    store_manager = StoreManager.query.filter_by(email=email).first()
    
    if not store_manager:
        return jsonify(error='Invalid email or password'), 401
    
    if store_manager.status != 'approved':
        return jsonify(error='Your request is pending approval. Please wait.'), 401
    
    if not check_password_hash(store_manager.password, password):
        return jsonify(error='Invalid email or password'), 401
    
    access_token = create_access_token(
        identity={'id': store_manager.id, 'email': store_manager.email, 'username': store_manager.username, 'role': store_manager.role,'status': store_manager.status }
    )
    
    return jsonify(access_token=access_token)

@app.route('/store-manager/chart-data', methods=['GET'])
@jwt_required()
def get_chart_data():
    try:
        current_user = get_jwt_identity()
        if 'store_manager' not in current_user.get('role', []):
            return jsonify({'error': 'Access denied. Only store managers can view chart data'}), 403

        products = Product.query.all()
        purchase_history = PurchaseHistory.query.all()

        stockData = {
            'labels': [product.name for product in products],
            'values': [product.quantity for product in products],
        }

        salesData = {
            'labels': [product.name for product in products],
            'values': [sum([purchase.quantity for purchase in purchase_history if purchase.product_id == product.id]) for product in products],
        }

        return jsonify({'stockData': stockData, 'salesData': salesData})
    except Exception as e:
        return jsonify({'error': 'An error occurred fetching chart data'}), 500


@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify(error='Missing email or password'), 400
    
    admin = Admin.query.filter_by(email=email).first()
    
    if not admin or not bcrypt.check_password_hash(admin.password, password):
        return jsonify(error='Invalid email or password'), 401
    
    if admin.username != 'admin':
        return jsonify(error='Invalid email or password'), 401
    
    access_token = create_access_token(
        identity={'id': admin.id, 'email': admin.email, 'username': admin.username, 'role': admin.role}
    )
    
    return jsonify(access_token=access_token)


@app.route('/admin/approve/<int:user_id>', methods=['PUT'])
@jwt_required()
def admin_approve_store_manager(user_id):
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        store_manager = StoreManager.query.get(user_id)

        if not store_manager:
            return jsonify(error='Store Manager not found'), 404

        store_manager.status = 'approved'
        db.session.commit()
        

        return jsonify(message='Store Manager approved'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/admin/reject/<int:user_id>', methods=['PUT'])
@jwt_required()
def admin_reject_store_manager(user_id):
    try:
        current_user = get_jwt_identity()
        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        store_manager = StoreManager.query.get(user_id)

        if not store_manager:
            return jsonify(error='Store Manager not found'), 404

        store_manager.status = 'rejected'
        db.session.commit()
        

        return jsonify(message='Store Manager rejected'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500
    

@app.route('/admin/pending-requests', methods=['GET'],endpoint='get_pending_store_manager_requests')
def get_pending_store_manager_requests():
    pending_requests = StoreManager.query.filter_by(status='pending').all()
    requests_data = [
        {
            'id': request.id,
            'username': request.username,
            'email': request.email,
            'status': request.status,
        }
        for request in pending_requests
    ]
    return jsonify(requests_data)

@app.route('/admin/all-requests', methods=['GET'], endpoint='get_all_store_manager_requests')
@jwt_required()
def get_all_store_manager_requests():
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        all_requests = StoreManager.query.all()
        requests_data = [
            {
                'id': request.id,
                'username': request.username,
                'email': request.email,
                'status': request.status,
            }
            for request in all_requests
        ]
        return jsonify(requests_data), 200

    except Exception as e:
        return jsonify(error=str(e)), 500



UPLOAD_FOLDER = 'C:\\Users\\DELL\\OneDrive\\Desktop\\mad2_project\\egrocery\\public'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

@app.route('/admin/create-category', methods=['POST'])
@jwt_required()
def create_category():
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        data = request.form  
        title = data.get('title')
        description = data.get('description')

        if not title:
            return jsonify(error='Title is required'), 400

        image = request.files['image']  

        if image and image.filename.split('.')[-1].lower() in ALLOWED_EXTENSIONS:
            filename = secure_filename(image.filename)
            image.save(os.path.join(UPLOAD_FOLDER, filename))
        else:
            filename = None
        new_category = Category(title=title, description=description, image_filename=filename)
        db.session.add(new_category)
        db.session.commit()

        return jsonify(message='Category created successfully'), 201
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/api/categories', methods=['GET'])
# @cache.cached(timeout=30)
def get_categories():
    try:
        categories = Category.query.all()

        serialized_categories = [{
            'id': category.id,
            'title': category.title,
            'description': category.description,
            'image_filename': category.image_filename
        } for category in categories]

        return jsonify(serialized_categories)
    except Exception as e:
        return jsonify(error=str(e)), 500
    
@app.route('/admin/edit-category/<int:category_id>', methods=['PUT'])
@jwt_required()
def edit_category(category_id):
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        title = request.form.get('title')
        description = request.form.get('description')

        category = Category.query.get(category_id)

        if not category:
            return jsonify(error='Category not found'), 404

        if title:
            category.title = title
        if description:
            category.description = description

        if 'image' in request.files:
            image = request.files['image']
            if image:
                filename = secure_filename(image.filename)
                image.save(os.path.join(UPLOAD_FOLDER, filename))
                category.image_filename = filename  

        db.session.commit()

        return jsonify(message='Category updated successfully'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/admin/delete-category/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        category = Category.query.get(category_id)

        if not category:
            return jsonify(error='Category not found'), 404

        if category.image_filename:
            image_path = os.path.join(UPLOAD_FOLDER, category.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)

        db.session.delete(category)
        db.session.commit()

        return jsonify(message='Category deleted successfully'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/api/products', methods=['GET'])
# @cache.cached(timeout=30)
def get_products():
    try:
        category_title = request.args.get('category')
        
        if category_title:
            products = Product.query.join(Category).filter(Category.title == category_title).all()
        else:
            products = Product.query.all()

        serialized_products = []
        for product in products:
            serialized_product = {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'quantity': product.quantity,
                'image_filename': product.image_filename,
                'category': {
                    'id': product.category.id,
                    'name': product.category.title
                }
            }
            serialized_products.append(serialized_product)

        return jsonify(serialized_products)
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/store-manager/add-product', methods=['POST'])
@jwt_required()
def add_product():
    try:
        current_user = get_jwt_identity()

        if 'store_manager' not in current_user.get('role', []):
            return jsonify(error='Access denied. Store Manager role required'), 403

        data = request.form
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        quantity = data.get('quantity')
        category_id = data.get('category_id')

        if not name or not price or not category_id:
            return jsonify(error='Missing required data for product creation'), 400

        category = Category.query.get(category_id)
        if not category:
            return jsonify(error='Category not found'), 404
        
        image = request.files['image']  

        if image and image.filename.split('.')[-1].lower() in ALLOWED_EXTENSIONS:
            filename = secure_filename(image.filename)
            image.save(os.path.join(UPLOAD_FOLDER, filename))
        else:
            filename = None
        new_product = Product(name=name, description=description, price=price, quantity=quantity, category=category,image_filename=filename)
        db.session.add(new_product)
        db.session.commit()

        return jsonify(message='Product added successfully'), 201
    except Exception as e:
        return jsonify(error=str(e)), 500
    

@app.route('/store-manager/edit-product/<product_id>', methods=["PUT"])
@jwt_required()
def edit_product(product_id):
    try:
        current_user = get_jwt_identity()

        if "store_manager" not in current_user.get('role', []):
            return jsonify(error='Access denied. Store Manager role required'), 403

        product = Product.query.get(product_id)

        if not product:
            return jsonify(error='Product not found'), 404

        name = request.form.get('name')
        if name:
            product.name = name

        description = request.form.get('description')
        if description:
            product.description = description

        price = request.form.get('price')
        if price:
            product.price = price
        
        quantity = request.form.get('quantity')
        if quantity:
            product.quantity = quantity

        category_id = request.form.get('category_id')
        if category_id:
            category = Category.query.get(category_id)
            if category:
                product.category = category

        if 'image' in request.files:
            image = request.files['image']
            if image:
                filename = secure_filename(image.filename)
                image.save(os.path.join(UPLOAD_FOLDER, filename))
                product.image_filename = filename

        db.session.commit()

        return jsonify(message='Product updated successfully'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/store-manager/delete-product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    try:
        current_user = get_jwt_identity()

        if 'store_manager' not in current_user.get('role', []):
            return jsonify(error='Access denied. Store Manager role required'), 403

        product = Product.query.get(product_id)

        if not product:
            return jsonify(error='Product not found'), 404

        if product.image_filename:
            image_path = os.path.join(UPLOAD_FOLDER, product.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)

        db.session.delete(product)
        db.session.commit()

        return jsonify(message='Product deleted successfully'), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/store-manager/request-category', methods=['POST'])
@jwt_required()
def request_category():
    try:
        current_user = get_jwt_identity()

        if 'store_manager' not in current_user.get('role', []):
            return jsonify(error='Access denied. Store Manager role required'), 403

        data = request.form
        title = data.get('title')
        description = data.get('description')
        if not title:
            return jsonify(error='Title is required'), 400
        
        if Category.query.filter_by(title=title).first():
            return jsonify(error='Category with this title already exists'), 400
        image = request.files['image']

        if image and image.filename.split('.')[-1].lower() in ALLOWED_EXTENSIONS:
            filename = secure_filename(image.filename)
            image.save(os.path.join(UPLOAD_FOLDER, filename))
        else:
            filename = None

        new_request = CategoryRequest(
            title=title,
            description=description,
            image_filename=filename,
            store_manager_id=current_user['id']
        )
        db.session.add(new_request)
        db.session.commit()

        return jsonify(message='Category request submitted successfully'), 201
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/store-manager/export-products', methods=['GET'])
@jwt_required()
def export_products():
    try:
        current_user = get_jwt_identity()
        if 'store_manager' not in current_user.get('role', []):
            return jsonify({'error': 'Access denied. Only store managers can export products'}), 403

        products = Product.query.all()
        purchase_history = PurchaseHistory.query.all()

        stock_remain = {}
        for purchase in purchase_history:
            if purchase.product_id not in stock_remain:
                product = Product.query.filter_by(id=purchase.product_id).first()
                stock_remain[purchase.product_id] = product.quantity if product else 0

            stock_remain[purchase.product_id] -= purchase.quantity

        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        csv_writer.writerow(["Product Name", "Stock Remaining", "Description", "Price", "Units Sold"])
        for product in products:
            remaining_quantity = stock_remain.get(product.id, product.quantity)
            csv_writer.writerow([product.name, str(remaining_quantity), product.description, str(product.price), str(purchase.quantity)])

        response = Response(
            csv_data.getvalue(),
            content_type='text/csv',
            headers={'Content-Disposition': 'attachment; filename=product_export.csv'}
        )

        return response

    except Exception as e:
        return jsonify({'error': 'An error occurred during product export'}), 500 
@app.route('/admin/category-requests', methods=['GET'])
@jwt_required()
def get_category_requests():
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        category_requests = CategoryRequest.query.filter_by(status='pending').all()
        requests_data = [
            {
                'id': request.id,
                'title': request.title,
                'description': request.description,
                'image_filename': request.image_filename,

            }
            for request in category_requests
        ]
        return jsonify(requests_data), 200

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/admin/approve-category-request/<int:request_id>', methods=['PUT'])
@jwt_required()
def approve_category_request(request_id):
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        category_request = CategoryRequest.query.get(request_id)

        if not category_request:
            return jsonify(error='Category request not found'), 404

        category_request.status = 'approved'

        new_category = Category(
            title=category_request.title,
            description=category_request.description,
            image_filename=category_request.image_filename,
        )

        db.session.add(new_category)
        db.session.commit()

        return jsonify(message='Category request approved'), 200

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/admin/reject-category-request/<int:request_id>', methods=['PUT'])
@jwt_required()
def reject_category_request(request_id):
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify(error='Access denied. Admin role required'), 403

        category_request = CategoryRequest.query.get(request_id)

        if not category_request:
            return jsonify(error='Category request not found'), 404

        category_request.status = 'rejected'
        db.session.commit()

        return jsonify(message='Category request rejected'), 200

    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/search', methods=['GET'])
def search():
    try:
        search_query = request.args.get('query')

        if not search_query:
            return jsonify(error="Missing Search Value"),400
        products = Product.query.filter(
            or_(
                Product.name.ilike(f'%{search_query}%'),
                Product.description.ilike(f'%{search_query}%')
            )
        ).all()
        categories = Category.query.filter(
            or_(
                Category.title.ilike(f'%{search_query}%'),
                Category.description.ilike(f'%{search_query}%')
            )
        ).all()
        serialized_products = [
            {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'quantity': product.quantity,
                'image_filename': product.image_filename,
                'category': {
                    'id': product.category.id,
                    'name': product.category.title,
                }
            }
            for product in products
        ]

        serialized_categories = [
            {
                'id': category.id,
                'title': category.title,
                'description': category.description,
                'image_filename': category.image_filename,
            }
            for category in categories
        ]
        search_results = {
            'products': serialized_products,
            'categories': serialized_categories,
        }

        return jsonify(search_results), 200

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/add-to-cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        data = request.get_json()

        user = User.query.filter_by(username=username).first()

        existing_item = None
        for cart_item in user.carts:
            if cart_item.product_id == data['product_id']:
                existing_item = cart_item
                break

        if existing_item:
            existing_item.quantity += data['quantity']
        else:
            cart_item = Cart(
                user=user,  
                product_id=data['product_id'],
                product_name=data['product_name'],
                product_image=data['product_image'],
                quantity=data['quantity'],
                product_price=data['product_price']
            )
            db.session.add(cart_item)

        db.session.commit()
        return jsonify(message='Added to Cart'), 200
    except Exception as e:
        return jsonify(error='An error occurred while adding to the cart'), 500

@app.route('/delete-from-cart', methods=['DELETE'])
@jwt_required()
def delete_from_cart():
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        user = User.query.filter_by(username=username).first()
        data = request.get_json()
        for cart_item in user.carts:
            if cart_item.product_id == data['product_id']:
                db.session.delete(cart_item)
                db.session.commit()  
                return jsonify(message='Product deleted from the cart'), 200

        return jsonify(error='Product not found in the cart'), 404

    except Exception as e:
        return jsonify(error='An error occurred while deleting from the cart'), 500
    
@app.route('/clear-cart', methods=['DELETE'])
@jwt_required()
def clear_cart():
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        user = User.query.filter_by(username=username).first()
        
        for cart_item in user.carts:
            db.session.delete(cart_item)
        
        db.session.commit()

        return jsonify(message='Cart cleared successfully'), 200
    except Exception as e:
        return jsonify(error='An error occurred while clearing the cart'), 500


@app.route('/get-cart', methods=['GET'])
@jwt_required()
def get_cart():
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        user = User.query.filter_by(username=username).first()
        cart_items = user.carts
        serialized_cart_items = [
            {
                'product_id': cart_item.product_id,
                'product_name': cart_item.product_name,
                'product_image': cart_item.product_image,
                'quantity': cart_item.quantity,
                'product_price': cart_item.product_price,
            }
            for cart_item in cart_items
        ]

        return jsonify(serialized_cart_items), 200
    except Exception as e:
        return jsonify(error='An error occurred while fetching the cart'), 500

@app.route('/buy-product', methods=['POST'])
@jwt_required()
def buy_product():
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        purchase_data = request.json.get('cart', [])

        for item in purchase_data:
            product_id = item['product_id']
            quantity = item['quantity']
            product_name = item['product_name']
            product_image = item['product_image']
            product_price = item['product_price']

            product = Product.query.get(product_id)

            if product and product.quantity >= quantity:
                product.quantity -= quantity
                db.session.commit()
                purchase = PurchaseHistory(
                    username=username,
                    product_id=product_id,
                    product_name=product_name,
                    product_image=product_image,
                    product_price=product_price,
                    quantity=quantity,
                )
                db.session.add(purchase)
            else:
                return jsonify({'error': f'Not enough quantity available for product with ID {product_id}'}), 400

        db.session.commit()

        return jsonify({'message': 'Products purchased successfully'}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred during purchase'}), 500

@app.route('/purchase-history/<username>', methods=['GET'])
# @cache.cached(timeout=5)
@jwt_required()
def get_purchase_history(username):
    try:
        current_user = get_jwt_identity()
        username = current_user['username']
        purchase_history = PurchaseHistory.query.filter_by(username=username).all()

        purchase_history_data = []
        for purchase in purchase_history:
            purchase_data = {
                'product_name': purchase.product_name,
                'product_image': purchase.product_image,
                'product_price': purchase.product_price,
                'quantity': purchase.quantity,
                'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d %H:%M:%S')
            }
            purchase_history_data.append(purchase_data)

        return jsonify(purchase_history_data)
    except Exception as e:
        return jsonify({'error': 'An error occurred while fetching purchase history'}), 500

@app.route('/store-manager/send-message', methods=['POST'])
@jwt_required()
def send_message():
    try:
        current_user = get_jwt_identity()
        sender = StoreManager.query.filter_by(username=current_user['username']).first()

        if sender.role != 'store_manager':
            return jsonify({'error': 'Only store managers can send messages'}), 403

        title = request.json.get('title')
        body = request.json.get('body')

        if not title or not body:
            return jsonify({'error': 'Title and body are required'}), 400

        recipient = Admin.query.filter_by(id=1).first()  

        message = Message(title=title, body=body, sender=sender, recipient=recipient)
        db.session.add(message)
        db.session.commit()

        return jsonify({'message': 'Message sent successfully'}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while sending the message'}), 500


@app.route('/admin/get-messages', methods=['GET'])
@jwt_required()
def get_messages():
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify({'error': 'Access denied. Only admins can fetch messages'}), 403

        messages = Message.query.filter_by(is_read=False, recipient_id=current_user['id']).all()
        message_list = []
        for message in messages:
            sender_username = message.sender.username if message.sender else 'Unknown'
            message_data = {
                'id': message.id,
                'title': message.title,
                'body': message.body,
                'sender_username': sender_username,
                'timestamp': message.timestamp.isoformat(),
            }
            message_list.append(message_data)
        return jsonify({'messages': message_list}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while fetching messages'}), 500

@app.route('/admin/mark-as-read', methods=['PUT'])
@jwt_required()
def mark_as_read():
    try:
        current_user = get_jwt_identity()

        if 'admin' not in current_user.get('role', []):
            return jsonify({'error': 'Access denied. Only admins can mark messages as read'}), 403

        message_id = request.json.get('message_id')
        if not message_id:
            return jsonify({'error': 'Message ID is required for marking as read'}), 400

        message = Message.query.get(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404

        message.is_read = True
        db.session.commit()

        return jsonify({'message': 'Message marked as read successfully'}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while marking the message as read'}), 500

if __name__ == '__main__':
    create_tables()  
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = bcrypt.generate_password_hash('admin_password').decode('utf-8')
        admin = Admin(username='admin', password=hashed_password, email='admin@gmail.com', role="admin")
        db.session.add(admin)
        db.session.commit()
    app.run(debug=True, port=5000)
