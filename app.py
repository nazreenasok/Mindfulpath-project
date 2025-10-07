import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from dotenv import load_dotenv
import requests
import uuid
# In a real application, you would install the cashfree-sdk
# For this example, we'll simulate the interaction.
# from cashfree_sdk.payouts.api_client import APIClient
# from cashfree_sdk.payouts.models.create_transfer_request import CreateTransferRequest

# Load environment variables from .env file
load_dotenv()

# --- APP INITIALIZATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a-very-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- MAIL CONFIGURATION for Reminders ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')


# --- EXTENSIONS INITIALIZATION ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login' # The route to redirect to for login
login_manager.login_message_category = 'info'


# --- DATABASE MODELS ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    phone_number = db.Column(db.String(20))
    guardian_details = db.Column(db.String(200)) # For minor patients
    role = db.Column(db.String(20), nullable=False, default='patient') # Roles: patient, doctor, admin

    appointments = db.relationship('Appointment', backref='patient', lazy=True)

    def __repr__(self):
        return f"User('{self.email}', '{self.role}')"

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('doctor_profile', uselist=False))
    specialization = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.Text) # Notes not visible to patients

    appointments = db.relationship('Appointment', backref='doctor', lazy=True)

    def __repr__(self):
        return f"Doctor('{self.user.full_name}', '{self.specialization}')"

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    service_category = db.Column(db.String(50), nullable=False) # e.g., Children, Teens, Adults
    service_type = db.Column(db.String(100), nullable=False) # e.g., Anxiety Consultation
    status = db.Column(db.String(20), nullable=False, default='booked') # e.g., booked, paid, completed, cancelled
    prescription = db.Column(db.Text) # Visible to patient
    reminder_sent_24h = db.Column(db.Boolean, default=False)
    reminder_sent_3h = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Appointment('{self.patient.full_name}' with '{self.doctor.user.full_name}' at '{self.appointment_time}')"

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    appointment = db.relationship('Appointment', backref=db.backref('payment', uselist=False))
    cashfree_order_id = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, successful, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- USER LOADER FOR FLASK-LOGIN ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- HELPER FUNCTIONS ---
def send_reminder_email(appointment):
    """Sends a reminder email to the patient."""
    try:
        patient = User.query.get(appointment.user_id)
        doctor = Doctor.query.get(appointment.doctor_id)
        msg = Message(
            'Appointment Reminder',
            recipients=[patient.email]
        )
        msg.body = f"""
        Hi {patient.full_name},

        This is a reminder for your upcoming appointment with Dr. {doctor.user.full_name}
        on {appointment.appointment_time.strftime('%Y-%m-%d at %I:%M %p')}.

        Thank you,
        Your Clinic
        """
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        return False

# --- API ROUTES ---
@app.route("/")
def home():
    return render_template("index.html")

# User Authentication
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(
        email=data['email'],
        password=hashed_password,
        full_name=data.get('full_name', ''),
        role=data.get('role', 'patient') # Can be 'patient' or 'doctor' on registration
    )
    db.session.add(user)
    db.session.commit()

    # If role is doctor, create a doctor profile
    if user.role == 'doctor' and 'specialization' in data:
        doctor = Doctor(user_id=user.id, specialization=data['specialization'])
        db.session.add(doctor)
        db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user, remember=True)
        return jsonify({'message': 'Login successful', 'role': user.role}), 200
    return jsonify({'message': 'Login failed. Check email and password.'}), 401

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/user', methods=['GET'])
@login_required
def get_user():
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'full_name': current_user.full_name,
        'role': current_user.role
    })

# Slot Booking and Management
@app.route('/api/doctors', methods=['GET'])
def get_doctors():
    doctors = Doctor.query.all()
    doctor_list = []
    for doc in doctors:
        doctor_list.append({
            'id': doc.id,
            'name': doc.user.full_name,
            'specialization': doc.specialization
        })
    return jsonify(doctor_list), 200

@app.route('/api/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    if current_user.role != 'patient':
        return jsonify({'message': 'Only patients can book appointments.'}), 403

    data = request.get_json()
    doctor_id = data['doctor_id']
    appointment_time_str = data['appointment_time'] # Expecting "YYYY-MM-DD HH:MM"
    appointment_time = datetime.strptime(appointment_time_str, '%Y-%m-%d %H:%M')

    # Check for conflicts
    existing_appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        appointment_time=appointment_time
    ).first()

    if existing_appointment:
        return jsonify({'message': 'This time slot is already booked.'}), 409

    appointment = Appointment(
        user_id=current_user.id,
        doctor_id=doctor_id,
        appointment_time=appointment_time,
        service_category=data['service_category'],
        service_type=data['service_type']
    )
    db.session.add(appointment)
    db.session.commit()
    
    # Placeholder for payment
    # In a real app, you'd create the payment order here
    return jsonify({
        'message': 'Appointment booked successfully. Proceed to payment.',
        'appointment_id': appointment.id
    }), 201


@app.route('/api/appointments', methods=['GET'])
@login_required
def get_appointments():
    if current_user.role == 'patient':
        appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    elif current_user.role == 'doctor':
        doctor_profile = Doctor.query.filter_by(user_id=current_user.id).first()
        appointments = Appointment.query.filter_by(doctor_id=doctor_profile.id).all()
    else: # Admin
        return jsonify({'message': 'Admins should use the admin dashboard route.'}), 403

    appointment_list = []
    for appt in appointments:
        appointment_list.append({
            'id': appt.id,
            'patient_name': appt.patient.full_name,
            'doctor_name': appt.doctor.user.full_name,
            'time': appt.appointment_time.isoformat(),
            'service': appt.service_type,
            'status': appt.status,
            'prescription': appt.prescription
        })
    return jsonify(appointment_list), 200


# Payment Gateway Integration (Cashfree)
@app.route('/api/payment/create_order', methods=['POST'])
@login_required
def create_payment_order():
    data = request.get_json()
    appointment_id = data['appointment_id']
    amount = data.get('amount', 1000.00) # Example amount

    # Here you would use the Cashfree SDK to create an order
    # This is a mock response
    cashfree_order_id = f"order_{datetime.now().timestamp()}"

    payment = Payment(
        appointment_id=appointment_id,
        cashfree_order_id=cashfree_order_id,
        amount=amount
    )
    db.session.add(payment)
    db.session.commit()

    # The response would contain details for your frontend to initialize Cashfree's payment popup
    return jsonify({
        'message': 'Payment order created.',
        'order_id': cashfree_order_id,
        'amount': amount,
        'currency': 'INR',
        # 'api_key': os.getenv('CASHFREE_API_KEY'), # Send key to frontend if needed
    }), 201

@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    # This endpoint is called by Cashfree when a payment status changes
    # You must validate the webhook signature here for security
    data = request.get_json()
    app.logger.info(f"Cashfree Webhook Received: {data}")
    
    order_id = data.get('orderId')
    transaction_status = data.get('transactionStatus')

    payment = Payment.query.filter_by(cashfree_order_id=order_id).first()
    if not payment:
        return jsonify({'message': 'Order not found'}), 404
        
    if transaction_status == 'SUCCESS':
        payment.status = 'successful'
        appointment = payment.appointment
        appointment.status = 'paid'
        db.session.commit()
    elif transaction_status == 'FAILED':
        payment.status = 'failed'
        db.session.commit()

    return jsonify({'status': 'ok'}), 200

# Doctor Dashboard
@app.route('/api/doctor/upload_prescription', methods=['POST'])
@login_required
def upload_prescription():
    if current_user.role != 'doctor':
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    appointment_id = data['appointment_id']
    prescription_text = data['prescription']

    appointment = Appointment.query.get(appointment_id)
    if not appointment:
        return jsonify({'message': 'Appointment not found'}), 404
        
    # Verify this doctor is assigned to this appointment
    doctor_profile = Doctor.query.filter_by(user_id=current_user.id).first()
    if appointment.doctor_id != doctor_profile.id:
        return jsonify({'message': 'You are not the doctor for this appointment.'}), 403

    appointment.prescription = prescription_text
    appointment.status = 'completed'
    db.session.commit()

    return jsonify({'message': 'Prescription uploaded successfully.'}), 200

# Admin Dashboard
@app.route('/api/admin/dashboard_data', methods=['GET'])
@login_required
def admin_dashboard_data():
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    users = User.query.filter_by(role='patient').all()
    appointments = Appointment.query.order_by(Appointment.appointment_time.desc()).all()

    user_data = [{
        'id': u.id,
        'name': u.full_name,
        'email': u.email,
        'age': u.age,
        'gender': u.gender,
        'phone': u.phone_number
    } for u in users]

    appointment_data = [{
        'id': a.id,
        'patient_name': a.patient.full_name,
        'doctor_name': a.doctor.user.full_name,
        'time': a.appointment_time.isoformat(),
        'status': a.status
    } for a in appointments]

    return jsonify({
        'users': user_data,
        'appointments': appointment_data
    }), 200


# --- SCHEDULER FOR REMINDERS (EXAMPLE) ---
# In a production app, this would run in a separate process or using a service like Celery.
# This is a simplified function to be triggered manually or via a cron job.
@app.route('/api/send_reminders')
def trigger_reminders():
    """Manually trigger the sending of reminders."""
    now = datetime.utcnow()
    
    # 24-hour reminders
    upcoming_24h = Appointment.query.filter(
        Appointment.appointment_time.between(now, now + timedelta(hours=24, minutes=30)),
        Appointment.reminder_sent_24h == False,
        Appointment.status == 'paid'
    ).all()

    for appt in upcoming_24h:
        if send_reminder_email(appt):
            appt.reminder_sent_24h = True
    
    # 3-hour reminders
    upcoming_3h = Appointment.query.filter(
        Appointment.appointment_time.between(now, now + timedelta(hours=3, minutes=30)),
        Appointment.reminder_sent_3h == False,
        Appointment.status == 'paid'
    ).all()
    
    for appt in upcoming_3h:
        if send_reminder_email(appt):
            appt.reminder_sent_3h = True

    db.session.commit()
    return jsonify({
        'message': 'Reminders sent.',
        '24h_reminders': len(upcoming_24h),
        '3h_reminders': len(upcoming_3h)
    }), 200

# --- MAIN RUN ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create a default admin user if one doesn't exist
        if not User.query.filter_by(email='admin@example.com').first():
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(
                email='admin@example.com',
                password=hashed_password,
                full_name='Admin User',
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True, host="0.0.0.0", port=5000)
