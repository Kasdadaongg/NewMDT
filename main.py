import json
import uuid
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Email

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Flask-Mail Setup
app.config['MAIL_SERVER'] = 'mail.privateemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'info@harpcityrpc.xyz'
app.config['MAIL_PASSWORD'] = 'info1234'
app.config['MAIL_DEFAULT_SENDER'] = 'info@harpcityrpc.xyz'
mail = Mail(app)
import json

def load_arrest_reports():
    try:
        with open('arrest_reports.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Load user data
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)


# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash, email, role, approved=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.role = role
        self.approved = approved

    def get_id(self):
        return self.id

# Load user by ID for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    for user_id_key, user_data in users.items():
        if user_data['id'] == user_id:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                password_hash=user_data['password'],
                email=user_data['email'],
                role=user_data['role'],
                approved=user_data['approved']
            )
    return None

# Flask-WTF Forms
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RoleForm(FlaskForm):
    role = SelectField('Select Role', choices=[('Garda', 'Garda'), ('EMS', 'EMS'), ('Fire Department', 'Fire Department'), ('Civ', 'Civ')], validators=[DataRequired()])
    submit = SubmitField('Assign Role')


@app.route('/', methods=['GET', 'POST'])
def main():


    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        users = load_users()
        user = None
        for user_id, user_data in users.items():
            if user_data['username'] == form.username.data:
                user = user_data
                break
        
        if user:
            print(f"DEBUG: User data found: {user}")  # Debugging line
            
            if check_password_hash(user['password'], form.password.data):
                user_obj = User(id=user['id'], username=user['username'], password_hash=user['password'], email=user['email'], role=user['role'], approved=user['approved'])
                if user_obj.approved:
                    login_user(user_obj)
                    return redirect(url_for('home'))
                else:
                    flash('Your account is awaiting approval by the admin.', 'warning')
            else:
                flash('Login failed. Check your username and/or password.', 'danger')
        else:
            flash('Login failed. No user found with that username.', 'danger')

    return render_template('login.html', form=form)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        users = load_users()
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(form.password.data)
        users[user_id] = {
            'id': user_id,
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password,
            'role': None,
            'approved': False
        }
        save_users(users)
        flash('Your account has been created! Awaiting approval from the admin.', 'success')
        
        # Send an email to admin about the new account
        msg = Message('New User Awaiting Approval', recipients=['admin@harpcityrpc.xyz'])
        msg.body = f"A new user {form.username.data} has registered. Please approve them from the admin panel."
        mail.send(msg)
        user = Message('New User Awaiting Approval', recipients=[form.email.data])
        user.body = f"Hello {form.username.data}! We have received your signup request. Our staff will review it and will let you know if your accepted/rejected"
        mail.send(user)
        # flash('Sign Up successful! Please fill out your application before proceeding.', 'success')

        # return redirect(url_for('apply'))  # Redirect the user to the application page after signup

    return render_template('signup.html', form=form)






@app.route('/character_lookup', methods=['GET', 'POST'])
@login_required
def character_lookup():
    character_data = None
    if request.method == 'POST':
        character_name = request.form['character_name']

        # Load users from the 'users.json' file
        users = load_users()

        # Search for the character by name within the current user's data
        for user_id, user in users.items():
            if user['username'] == current_user.username:
                # Find the character by name for the current user
                for character in user.get('characters', []):
                    if character['name'].lower() == character_name.lower():
                        character_data = character
                        break
                if character_data:
                    break

    return render_template('character_lookup.html', vehicle_data=character_data)


@app.route('/view_arrest_reports')
@login_required
def view_arrest_reports():
    if current_user.role != 'Garda':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Load the arrest reports
    arrest_reports = load_arrest_reports()

    return render_template('view_arrest_reports.html', arrest_reports=arrest_reports)

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Load all users instead of filtering for unapproved ones
    users = load_users()  # Make sure this function returns all users

    return render_template('admins.html', users=users)  # Use the correct template name


# @app.route('/admin/approve_user/<user_id>', methods=['POST'])
# @login_required
# def approve_user(user_id):
#     if current_user.role != 'admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('home'))

#     users = load_users()
#     if user_id in users:
#         users[user_id]['approved'] = True
#         save_data('users.json', users)
#         flash(f'User {users[user_id]["username"]} has been approved!', 'success')
#     return redirect(url_for('approve_users'))

@app.route('/admin/assign_role/<user_id>', methods=['GET', 'POST'])
@login_required
def assign_role(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        role = request.form['role']
        users = load_users()

        if user_id in users:
            users[user_id]['role'] = role
            save_data('users.json', users)
            flash(f'User {users[user_id]["username"]} role has been updated to {role}.', 'success')

        return redirect(url_for('admin_panel'))

    return render_template('admins.html', user_id=user_id)


# Incident data management
def load_incidents():
    try:
        with open('incidents.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_incidents(incidents):
    with open('incidents.json', 'w') as f:
        json.dump(incidents, f, indent=4)

# Route to show incidents
@app.route('/incidents')
@login_required
def incidents():
    incidents = load_incidents()
    return render_template('incidents.html', incidents=incidents)

# Route to add a new incident
@app.route('/incidents/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    if current_user.role != 'admin' and current_user.role != 'Garda':
        flash('You do not have permission to create an incident.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        incidents = load_incidents()
        incident_id = str(uuid.uuid4())
        title = request.form['title']
        description = request.form['description']
        
        incidents[incident_id] = {
            'id': incident_id,
            'title': title,
            'description': description
        }

        save_incidents(incidents)
        flash('Incident created successfully!', 'success')
        return redirect(url_for('incidents'))

    return render_template('new_incident.html')


def save_bolo_report(title, description):
    bolo_reports = load_bolo_reports()
    bolo_reports.append({'title': title, 'description': description})
    save_data('bolo_reports.json', bolo_reports)

def load_bolo_reports():
    return load_data('bolo_reports.json')

def save_arrest_report(first_name, last_name, dob, mugshot_url, reason_for_arrest):
    arrest_reports = load_arrest_reports()
    arrest_reports.append({'first_name': first_name, 'last_name': last_name, 'dob': dob, 'mugshot_url': mugshot_url, 'reason_for_arrest': reason_for_arrest})
    save_data('arrest_reports.json', arrest_reports)

def load_arrest_reports():
    return load_data('arrest_reports.json')

def save_vehicle(user_id, vehicle_data):
    users = load_users()
    user = users.get(user_id)

    if user:
        if 'vehicles' not in user:
            user['vehicles'] = []  # Initialize the vehicles list if it doesn't exist

        user['vehicles'].append(vehicle_data)  # Add the new vehicle

        save_users(users)  # Save updated users data back to file
    else:
        print(f"User with ID {user_id} not found.")

def load_vehicles():
    return load_data('vehicles.json')

def save_character(user_id, character_data):
    users = load_users()
    user = users.get(user_id)

    if user:
        if 'characters' not in user:
            user['characters'] = []  # Initialize the characters list if it doesn't exist

        user['characters'].append(character_data)  # Add the new character

        save_users(users)  # Save updated users data back to file
    else:
        print(f"User with ID {user_id} not found.")


def load_characters():
    return load_data('characters.json')

def save_data(file_name, data):
    with open(file_name, 'w') as f:
        json.dump(data, f, indent=4)

def load_data(file_name):
    try:
        with open(file_name, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []



# Route to edit an incident
@app.route('/incidents/edit/<incident_id>', methods=['GET', 'POST'])
@login_required
def edit_incident(incident_id):
    if current_user.role != 'admin' and current_user.role != 'Garda':
        flash('You do not have permission to edit an incident.', 'danger')
        return redirect(url_for('home'))

    incidents = load_incidents()
    incident = incidents.get(incident_id)
    if not incident:
        flash('Incident not found.', 'danger')
        return redirect(url_for('incidents'))

    if request.method == 'POST':
        incident['title'] = request.form['title']
        incident['description'] = request.form['description']
        save_incidents(incidents)
        flash('Incident updated successfully!', 'success')
        return redirect(url_for('incidents'))

    return render_template('edit_incident.html', incident=incident)

# Route to delete an incident
@app.route('/incidents/delete/<incident_id>', methods=['POST'])
@login_required
def delete_incident(incident_id):
    if current_user.role != 'admin' and current_user.role != 'Garda':
        flash('You do not have permission to delete an incident.', 'danger')
        return redirect(url_for('home'))

    incidents = load_incidents()
    if incident_id in incidents:
        del incidents[incident_id]
        save_incidents(incidents)
        flash('Incident deleted successfully!', 'success')
    else:
        flash('Incident not found.', 'danger')

    return redirect(url_for('incidents'))
def get_vehicle_by_license_plate(license_plate):
    # Load the list of vehicles (assuming it's stored in a JSON file)
    vehicles = load_vehicles()
    
    # Search for the vehicle with the matching license plate
    for vehicle in vehicles:
        if vehicle['license_plate'] == license_plate:
            return vehicle  # Return the vehicle if a match is found
    
    return None  # Return None if no vehicle with the license plate is found

@app.route('/garda/bolo', methods=['GET', 'POST'])
@login_required
def bolo():
    if current_user.role != 'Garda':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Handle form submission to create a new BOLO
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        # You can add more fields as necessary
        # Save to database or a JSON file
        save_bolo_report(title, description)
        flash('BOLO report created successfully!', 'success')
        return redirect(url_for('bolo'))

    # Display BOLO reports
    bolo_reports = load_bolo_reports()
    return render_template('bolo.html', bolo_reports=bolo_reports)
@app.route('/garda/vehicle_lookup', methods=['GET', 'POST'])
@login_required
def vehicle_lookup():
    if current_user.role != 'Garda':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    vehicle_data = None
    if request.method == 'POST':
        license_plate = request.form['license_plate']
        # Lookup vehicle by license plate (you could query the vehicles database or a JSON file)
        vehicle_data = get_vehicle_by_license_plate(license_plate)

    return render_template('vehicle_lookup.html', vehicle_data=vehicle_data)

@app.route('/garda/arrest_report', methods=['GET', 'POST'])
@login_required
def arrest_report():
    if current_user.role != 'Garda':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        mugshot_url = request.form['mugshot_url']
        reason_for_arrest = request.form['reason_for_arrest']
        
        # Save arrest report to database or a JSON file
        save_arrest_report(first_name, last_name, dob, mugshot_url, reason_for_arrest)
        flash('Arrest report created successfully!', 'success')
        return redirect(url_for('arrest_report'))

    arrest_reports = load_arrest_reports()  # Load previously created arrest reports
    return render_template('arrest_report.html', arrest_reports=arrest_reports)

@app.route('/create_character', methods=['GET', 'POST'])
@login_required
def create_character():
    if current_user.role != 'Civ':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Get data from the form
        name = request.form['name']
        age = request.form['age']
        gender = request.form['gender']
        occupation = request.form['occupation']
        description = request.form['description']

        # Create character data
        character_data = {
            'name': name,
            'age': age,
            'gender': gender,
            'occupation': occupation,
            'description': description
        }

        # Save character data to the user's record
        save_character(current_user.id, character_data)

        flash(f'Character {name} has been created!', 'success')
        return redirect(url_for('home'))

    return render_template('create_character.html')

def load_crime_reports():
    try:
        with open('crime_reports.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

def save_crime_report(report):
    crime_reports = load_crime_reports()
    crime_reports.append(report)
    with open('crime_reports.json', 'w') as file:
        json.dump(crime_reports, file, indent=4)

@app.route('/create_vehicle', methods=['GET', 'POST'])
@login_required
def create_vehicle():
    if current_user.role != 'Civ':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Get data from the form
        license_plate = request.form['license_plate']
        make = request.form['make']
        model = request.form['model']
        color = request.form['color']
        year = request.form['year']
        owner = request.form['owner']

        # Create vehicle data
        vehicle_data = {
            'license_plate': license_plate,
            'make': make,
            'model': model,
            'color': color,
            'year': year,
            'owner': owner
        }

        # Save vehicle data to the user's record
        save_vehicle(current_user.id, vehicle_data)

        flash(f'Vehicle with license plate {license_plate} has been created!', 'success')
        return redirect(url_for('home'))

    return render_template('create_vehicle.html')

@app.route('/report_crime', methods=['GET', 'POST'])
@login_required
def report_crime():
    if current_user.role != 'Civ':
        flash('You must be a Civ to report a crime.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        crime_type = request.form['crime_type']
        description = request.form['description']

        # Save crime data (to a JSON file or database)
        crime_report = {
            'user_id': current_user.id,
            'crime_type': crime_type,
            'description': description,
            'status': 'Pending'
        }
        save_crime_report(crime_report)  # Assuming a function to save reports

        flash('Your crime report has been submitted.', 'success')
        return redirect(url_for('home'))

    return render_template('report_crime.html')

@app.route('/garda/view_reports', methods=['GET'])
@login_required
def view_reports():
    if current_user.role != 'Garda':
        flash('You must be a Garda to view crime reports.', 'danger')
        return redirect(url_for('home'))

    crime_reports = load_crime_reports()  # Assuming a function that loads crime reports
    return render_template('view_reports.html', crime_reports=crime_reports)

# Load users data from a JSON file
def load_users():
    with open('users.json', 'r') as f:
        return json.load(f)

# Save users data back to the JSON file
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)

@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        # Get data from form
        bio = request.form['bio']
        reason = request.form['reason']
        username = 'SomeUsername'  # Replace with actual username (e.g., current_user.username)

        # Load existing users from JSON file
        users = load_users()

        # Check if user already exists or needs a new unique user ID
        user_id = str(uuid.uuid4())  # Generate a unique user ID
        users[user_id] = {
            'username': username,
            'bio': bio,
            'reason': reason,
            'role': 'Civ',  # Default role
            'status': 'awaiting_approval',
            'approved': False  # Not approved initially
        }

        # Save the updated user data
        save_users(users)

        flash('Your application has been submitted and is awaiting approval.')
        return redirect(url_for('login'))

    return render_template('apply.html')

# @app.route('/approve_users', methods=['GET'])
# @login_required
# def approve_users():
#     if current_user.role != 'admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('home'))

#     # Get all users awaiting approval
#     unapproved_users = User.query.filter_by(status='awaiting_approval').all()
#     return render_template('approve_users.html', unapproved_users=unapproved_users)


@app.route('/approve_user/<user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    users = load_users()  # Load all users
    user = users.get(user_id)  # Get the user by ID

    if user and not user.get('approved', False):  # Check if user is not already approved
        user['approved'] = True  # Set status to approved (use boolean True)
        flash(f'User {user["username"]} has been approved!', 'success')
        save_users(users)  # Save changes to the file
        # Send rejection email
        msg = Message('Signup Request Accepted', recipients=[user['email']])
        msg.body = f"Hello {user['username']}! Welcome To HarpCityRPC, We are happy to inform you that you have been accepted into HarpCityRPC."
        mail.send(msg)  # Send the email
    else:
        flash('User not found or already approved.', 'danger')
        
    return redirect(url_for('admin_panel'))  # Redirect to the admin panel

@app.route('/reject_user/<user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    users = load_users()  # Load all users
    user = users.get(user_id)  # Get the user by ID

    if user:
        user['approved'] = False  # Set status to rejected (use boolean False)
        flash(f'User {user["username"]} has been rejected!', 'danger')
        save_users(users)  # Save changes to the file

        # Send rejection email
        msg = Message('Signup Request Rejected', recipients=[user['email']])
        msg.body = f"Hello {user['username']}! We regret to inform you that your signup request has been rejected."
        mail.send(msg)  # Send the email

    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_panel'))  # Redirect to the admin panel



if __name__ == '__main__':
    app.run(debug=True)
