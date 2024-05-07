from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'

instance_path = os.path.join(app.root_path, 'instance')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "database.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def create_uploads_folder():
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

with app.app_context():
    create_uploads_folder()

if not os.path.exists(instance_path):
    os.makedirs(instance_path)

db = SQLAlchemy(app)

class User(db.Model):
    username = db.Column(db.String(10), primary_key=True)  #Phone_number
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(20))

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(50))
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    amount = db.Column(db.Float)
    username = db.Column(db.String(10))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    img = db.Column(db.String(500))

class Organizations(db.Model):
    organization_name = db.Column(db.String(50))
    email = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(20))
    orghead = db.Column(db.String(20))

with app.app_context():
    db.create_all()

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session and 'email' not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)

    return decorated_function

def org_login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'email' not in session or 'is_org' not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)

    return decorated_function

@app.route('/')
def home():
    username = session.get('username')
    name = session.get('name')

    if 'email' in session:
        organization = Organizations.query.filter_by(email=session['email']).first()
        if organization:
            return render_template('home.html', name=organization.organization_name, username=session['email'], is_org=True)

    user = User.query.filter_by(username=username).first()
    return render_template('home.html', name=name, username=username, is_org=False)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('registration.html', error=error)

        new_user = User(username=username, name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        session['username'] = username
        session['name'] = name
        return redirect(url_for('home'))

    return render_template('registration.html')


def authenticate_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user.name
    return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            if user.password == password:
                session['username'] = username
                name = authenticate_user(username)
                if name is not None:
                    session['name'] = name
                return redirect(url_for('home'))
            else:
                error = "Invalid password. Please try again."
        else:
            error = "Username is not registered with us. Please try again."

    return render_template('login.html', error=error)

@app.route('/org_login', methods=['POST'])
def org_login():
    error = None
    if request.method == 'POST':
        email = request.form['org_email']
        password = request.form['org_password']
        organization = Organizations.query.filter_by(email=email).first()

        if organization and organization.password == password:
            session['email'] = email
            session['is_org'] = True  
            return redirect(url_for('home'))
        else:
            error = "Invalid organization credentials. Please try again."

    return render_template('login.html', error=error)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('forgot_password.html', error=error)

        user = User.query.filter_by(username=username).first()

        if user:
            user.password = password
            db.session.commit()
            return redirect(url_for('login'))
        else:
            error = "User not found. Please try again."
            return render_template('forgot_password.html', error=error)

    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('name', None)
    session.pop('email', None)
    return redirect(url_for('home'))

@app.route('/donate', methods=['GET', 'POST'])
@login_required
def donate():
    if request.method == 'POST':
        user_name = request.form['user_name']
        username = request.form['username']
        user_email = request.form['user_email']
        organization_name = request.form['organization_name']
        donation_amount = float(request.form['donation_amount'])

        # Organization
        is_organization = 'email' in session

        if is_organization:
            organization = Organizations.query.filter_by(email=session['email']).first()
            if organization:
                new_donation = Donation(organization_name=organization_name, amount=donation_amount,
                                        email=session['email'], date=datetime.utcnow())
                db.session.add(new_donation)
                db.session.commit()
                return redirect(url_for('make_payment'))
        else:
            # User
            user = User.query.filter_by(username=username).first()
            if user:
                new_donation = Donation(organization_name=organization_name, name=user.name, email=user_email,
                                        amount=donation_amount, username=username, date=datetime.utcnow())
                db.session.add(new_donation)
                db.session.commit()
                return redirect(url_for('make_payment'))

    organizations = Organizations.query.all()
    organization_names = [org.organization_name for org in organizations]

    user_name = session.get('name')
    username = session.get('username')

    return render_template('donate.html', user_name=user_name, username=username, organization_names=organization_names)

@app.route('/make_payment', methods=['GET', 'POST'])
@login_required
def make_payment():
    if request.method == 'POST':
        if 'payment_screenshot' not in request.files:
            return redirect(request.url)

        payment_screenshot = request.files['payment_screenshot']

        if payment_screenshot.filename == '':
            return redirect(request.url)

        identifier = session.get('username') if 'username' in session else session.get('email')
        filename = f"{identifier}_{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}_{secure_filename(payment_screenshot.filename)}"

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        payment_screenshot.save(file_path)
        organization_name = session.get('organization_name')
        name = session.get('name')
        email = session.get('email')
        username = session.get('username')
        amount = session.get('donation_amount')

        new_donation = Donation(
            organization_name=organization_name,
            name=name,
            email=email,
            amount=amount,
            username=username,
            date=datetime.utcnow(),
            img=filename  
        )
        db.session.add(new_donation)
        db.session.commit()

        return redirect(url_for('thanku'))

    return render_template('payments.html')


@app.route('/thanku')
@login_required
def thanku():
    return render_template('thanku.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        admin_email = request.form['admin_email']
        admin_password = request.form['admin_password']
        if admin_email == 'admin@ax.com' and admin_password == 'ax':
            session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid admin credentials. Please try again.'

    return render_template('admin_login.html', error=error)

@app.route('/admin/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        return redirect(url_for('contact_us'))

    return render_template('contact_us.html')

@app.route('/review')
@login_required
def review():
    return render_template('review.html')

@app.route('/new_organization', methods=['GET', 'POST'])
@login_required
def new_organization():
    if request.method == 'POST':
        organization_name = request.form['organization_name']
        email = request.form['email']
        password = request.form['password']
        orghead = request.form['orghead']

        existing_org = Organizations.query.filter_by(email=email).first()
        if existing_org:
            error = 'Organization with this email already exists. Please use a different email.'
        else:
            new_organization = Organizations(organization_name=organization_name, orghead=orghead, email=email, password=password)
            db.session.add(new_organization)
            db.session.commit()
            return redirect(url_for('review'))

    return render_template('new_organization.html')

@app.route('/view_organizations')
def view_organizations():
    organizations = Organizations.query.all()
    return render_template('organizations.html', organizations=organizations)

#users table
@app.route('/admin/users')
def list_users():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
def add_user():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('add_user.html', error=error)

        new_user = User(username=username, name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('list_users'))

    return render_template('add_user.html')

@app.route('/admin/users/edit/<string:username>', methods=['GET', 'POST'])
def edit_user(username):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    user = User.query.get_or_404(username)

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']

        user.name = name
        user.email = email

        db.session.commit()

        return redirect(url_for('list_users'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<string:username>', methods=['POST'])
def delete_user(username):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()

    return redirect(url_for('list_users'))

# Donations table
@app.route('/admin/donations')
def list_donations():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    donations = Donation.query.all()
    return render_template('donations.html', donations=donations)

@app.route('/admin/donations/add', methods=['GET', 'POST'])
def add_donation():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    if request.method == 'POST':
        organization_name = request.form['organization_name']
        name = request.form['name']
        email = request.form['email']
        amount = float(request.form['amount'])
        username = request.form['username']

        new_donation = Donation(organization_name=organization_name, name=name, email=email,
                                amount=amount, username=username, date=datetime.utcnow())
        db.session.add(new_donation)
        db.session.commit()

        return redirect(url_for('list_donations'))

    return render_template('add_donation.html')

@app.route('/admin/donations/edit/<int:donation_id>', methods=['GET', 'POST'])
def edit_donation(donation_id):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    donation = Donation.query.get_or_404(donation_id)

    if request.method == 'POST':
        organization_name = request.form['organization_name']
        name = request.form['name']
        email = request.form['email']
        amount = float(request.form['amount'])
        username = request.form['username']

        donation.organization_name = organization_name
        donation.name = name
        donation.email = email
        donation.amount = amount
        donation.username = username

        db.session.commit()

        return redirect(url_for('list_donations'))

    return render_template('edit_donation.html', donation=donation)

@app.route('/admin/donations/delete/<int:donation_id>', methods=['POST'])
def delete_donation(donation_id):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    donation = Donation.query.get_or_404(donation_id)
    db.session.delete(donation)
    db.session.commit()

    return redirect(url_for('list_donations'))

# Organizations table
@app.route('/admin/organizations')
def list_organizations():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    organizations = Organizations.query.all()
    return render_template('organizations.html', organizations=organizations)

@app.route('/admin/organizations/add', methods=['GET', 'POST'])
def add_organization():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    if request.method == 'POST':
        organization_name = request.form['organization_name']
        email = request.form['email']
        password = request.form['password']

        existing_org = Organizations.query.filter_by(email=email).first()
        if existing_org:
            error = 'Organization with this email already exists. Please use a different email.'
            return render_template('add_organization.html', error=error)

        new_organization = Organizations(organization_name=organization_name, email=email, password=password)
        db.session.add(new_organization)
        db.session.commit()

        return redirect(url_for('list_organizations'))

    return render_template('add_organization.html')

@app.route('/admin/organizations/edit/<string:email>', methods=['GET', 'POST'])
def edit_organization(email):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    organization = Organizations.query.get_or_404(email)

    if request.method == 'POST':
        organization_name = request.form['organization_name']
        password = request.form['password']

        organization.organization_name = organization_name
        organization.password = password

        db.session.commit()

        return redirect(url_for('list_organizations'))

    return render_template('edit_organization.html', organization=organization)

@app.route('/admin/organizations/delete/<string:email>', methods=['POST'])
def delete_organization(email):
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('home'))

    organization = Organizations.query.get_or_404(email)
    db.session.delete(organization)
    db.session.commit()

    return redirect(url_for('list_organizations'))


if __name__ == '__main__':
    app.run()
sq