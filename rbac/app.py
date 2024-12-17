from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager, current_user
import csv
from werkzeug.security import generate_password_hash, check_password_hash

# Initializing Flask 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite Database for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Defining  roles
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Storing password as plain text
    role = db.Column(db.String(50), nullable=False)

with app.app_context():
    db.create_all()
    if User.query.count() == 0:

        admin_user = User(username='admin', email='admin@email.com', password=generate_password_hash('admin123', method='pbkdf2:sha256', salt_length=8), role='admin')
        researcher_user = User(username='researcher', email='researcher@email.com', password=generate_password_hash('researcher123', method='pbkdf2:sha256', salt_length=8), role='researcher')

        db.session.add_all([admin_user, researcher_user])
        db.session.commit()

@app.route('/user_details', methods=['GET'])
def user_details():
    tasks = User.query.order_by(User.username).all()
    return render_template('user_details.html', tasks=tasks)

@app.route('/update_user/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    user = User.query.get_or_404(id)  # Fetch user from the database
    if request.method == 'POST':
        # Update user attributes from form data
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        
        try:
            db.session.commit()  # Commit changes to the database
            return redirect(url_for('user_details'))  # Redirect to the user details page
        except Exception as e:
            return f"An error occurred while updating the user: {str(e)}"

    # Render template for GET request
    return render_template('update.html', user=user)

@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect('user_details')
    except:
        return 'There was a problem deleting that user'


# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('dashboard.html') 

@app.route('/about')
def about():
    return render_template('about.html') 

@app.route('/explore')
def explore():
    return render_template('explore.html')  

@app.route('/user')
def user():
    return render_template('user.html')

@app.route('/about_user')
def about_user():
    return render_template('about_user.html')

@app.route('/explore_user')
def explore_user():
    return redirect(url_for('show_csv', role='user'))

# Admin-only route
@app.route('/admin')
def admin():
  #  print(current_user.role)
    current_user.role='admin'
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    return render_template('admin.html')

@app.route('/about_admin')
def about_admin():
    return render_template('about_admin.html')

@app.route('/explore_admin')
def explore_admin():
    current_user.role='admin'
    return redirect(url_for('show_csv', role='admin'))


#researcher-only route
@app.route('/researcher')
def researcher():
    return render_template('researcher.html')

@app.route('/about_researcher')
def about_researcher():
    return render_template('about_researcher.html')

@app.route('/explore_researcher')
def explore_researcher():
    return redirect(url_for('show_csv', role='researcher'))

@app.route('/show_csv')
def show_csv():
    role = request.args.get('role')
    data = []
    headers = [] 
    with open('dataset/Almora.csv', mode='r') as file:
        csv_reader = csv.reader(file)
        headers = next(csv_reader)
        rows = list(csv_reader)  # Read all rows
        if role=='admin' or role=='researcher':
            data = rows[:30]
        else:
            headers = headers[:10]  
            data = [row[:10] for row in rows[:10]]  # only first 10 rows will be accessable

    return render_template('explore_admin.html', headers=headers, data=data, role=role)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        print(user.role)
        current_user=User(username=user.username, email=user.email, password=user.password, role=user.role) 
        if user and check_password_hash(user.password, password):
            # login_user(user)
            if user.role == 'admin':
                return render_template('admin.html')
            if user.role == 'researcher':
                return render_template('researcher.html')
            return render_template('user.html')
        print("Invalid email or password. Please try again.")
    return render_template('sign.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = 'user'  # Always assign 'user' role to new registrations
        password = request.form['password']

        # Create new user
        new_user = User(username=username, email=email,password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8), role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)