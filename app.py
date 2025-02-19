from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Step 1: Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobs.db'  # Database Configuration
app.config['SECRET_KEY'] = 'your_secret_key'  # Security Key

# Step 2: Initialize Database and Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Step 3: Define User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Step 4: Define Job Application Model
class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(150), nullable=False)
    job_title = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Applied')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Step 5: Load User for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Step 6: Home Route
@app.route('/')
def home():
    if current_user.is_authenticated:
        jobs = JobApplication.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', jobs=jobs)
    return redirect(url_for('login'))

# Step 7: Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials')
    return render_template('login.html')

# Step 8: Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Step 9: Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Step 10: Add Job Application Route
@app.route('/add_job', methods=['POST'])
@login_required
def add_job():
    company = request.form['company']
    job_title = request.form['job_title']
    status = request.form['status']
    new_job = JobApplication(company=company, job_title=job_title, status=status, user_id=current_user.id)
    db.session.add(new_job)
    db.session.commit()
    return redirect(url_for('home'))

# Step 11: Run the Application
if __name__ == '__main__':
    with app.app_context():  # Ensure application context is set
        db.create_all()
    app.run(debug=True)
