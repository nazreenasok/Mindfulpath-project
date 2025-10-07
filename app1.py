import os
import uuid
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required
)
from flask_mail import Mail, Message
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import base64
from datetime import datetime, timezone

# ---------------- CONFIG ---------------- #
# Get the directory where the current script is
basedir = os.path.abspath(os.path.dirname(__file__))

# Load the .env file explicitly
load_dotenv(os.path.join(basedir, ".env"))

app = Flask(__name__, template_folder='templates')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail config (set in .env)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # email
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # app password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Cashfree config
CASHFREE_CLIENT_ID = os.getenv('CASHFREE_CLIENT_ID')
CASHFREE_CLIENT_SECRET = os.getenv('CASHFREE_CLIENT_SECRET')
CASHFREE_API_URL = "https://sandbox.cashfree.com/pg/orders"
CASHFREE_API_VERSION = "2022-09-01"

# ---------------- INIT ---------------- #
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------------- MODELS ---------------- #
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    guardian_name = db.Column(db.String(100))
    guardian_email = db.Column(db.String(120))
    guardian_phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='patient')

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service = db.Column(db.String(100), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)  # datetime of appointment
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ---------------- #

@app.route('/')
def home():
    # Renders the updated index.html (Homepage)
    return render_template('index.html')

# --- Frontend Navigation Routes (Render Static Pages) ---

@app.route('/about-us')
def about_us():
    return render_template('about_us.html')

@app.route('/services')
def services():
    return render_template('services.html')

# Change this route to match the file name and links
@app.route('/contact-us') # <-- FIX 1
def contact():
    # Make sure this renders the correct file name
    return render_template('contact_us.html') # <-- FIX 2

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_patient'))

    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()

        user = User.query.filter_by(email=email).first()

        # Debug
        print("Entered email:", email)
        print("Entered password:", password)
        if user:
            print("Stored hash:", user.password)
            print("Password matches:", bcrypt.check_password_hash(user.password, password))
        else:
            print("User not found")

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_patient'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_patient'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        age = request.form.get('age')
        gender = request.form.get('gender')
        phone = request.form.get('phone')
        guardian_name = request.form.get('guardian_name')
        guardian_email = request.form.get('guardian_email')
        guardian_phone = request.form.get('guardian_phone')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(
            name=name,
            email=email,
            password=hashed_password,
            age=age,
            gender=gender,
            phone=phone,
            guardian_name=guardian_name,
            guardian_email=guardian_email,
            guardian_phone=guardian_phone
        )
        from sqlalchemy.exc import IntegrityError
        try:
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("That email is already registered. Try logging in instead.", "danger")
            return redirect(url_for("signup"))

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard_patient():
    return render_template('dashboard_patient.html', user=current_user)
@app.route('/book-appointment', methods=['GET'])
@login_required
def book_appointment():
    return render_template('book_appointment.html', user=current_user)


# Save appointment after successful payment
@app.route('/confirm-appointment', methods=['POST'])
@login_required
def confirm_appointment():
    data = request.get_json()
    service = data.get('service')
    date_str = data.get('date')  # format: YYYY-MM-DD
    time_str = data.get('time')  # format: HH:MM

    if not service or not date_str or not time_str:
        return jsonify({"error": "Missing data"}), 400

    from datetime import datetime
    appointment_datetime = datetime.fromisoformat(f"{date_str}T{time_str}")
    appointment_datetime_utc = appointment_datetime.astimezone(timezone.utc)

    # Check if the slot is already booked for the same service
    existing = Appointment.query.filter_by(
        service=service,
        appointment_date=appointment_datetime_utc
    ).first()

    if existing:
        return jsonify({"error": "This slot is already booked. Please choose another."}), 409

    new_appt = Appointment(
        user_id=current_user.id,
        service=service,
        appointment_date=appointment_datetime_utc
    )
    db.session.add(new_appt)
    db.session.commit()

    return jsonify({"success": True})



@app.route('/my-appointments')
@login_required
def my_appointments():
    now = datetime.now(timezone.utc)

    # Query appointments for the current user
    now = datetime.now(timezone.utc)
    upcoming_appointments = Appointment.query.filter(
    Appointment.user_id == current_user.id,
    Appointment.appointment_date >= now
).order_by(Appointment.appointment_date.asc()).all()

    past_appointments = Appointment.query.filter(
    Appointment.user_id == current_user.id,
    Appointment.appointment_date < now
).order_by(Appointment.appointment_date.desc()).all()

    return render_template(
        'my_appointments.html',
        upcoming_appointments=upcoming_appointments,
        past_appointments=past_appointments,
        user=current_user
    )

# ----------- PASSWORD RESET (NEW) ----------- #

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='reset-password')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request", recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgotpassword.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('updatepassword.html', token=token)
    
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('updatepassword.html', token=token)

# ----------- CASHFREE INTEGRATION ----------- #
from urllib.parse import urlencode
@app.route('/create-cashfree-order', methods=['POST'])
@login_required
def create_cashfree_order():
    data = request.get_json()
    service = data.get('service')
    date_str = data.get('date')    # YYYY-MM-DD
    time_str = data.get('time')    # HH:MM
       # ✅ define order_id here
    order_id = f"order_{uuid.uuid4()}"
    params = {
    "order_id": order_id,
    "service": service,
    "date": date_str,
    "time": time_str    
    }
    query = urlencode(params)

    price = 1250.00
    if "therapy" in service.lower():
        price = 1500.00
    elif "consultation" in service.lower():
        price = 1200.00
    elif "Psychological and Psychiatric Services" in service.lower():
        price = 2500.00
    elif "Couples Counseling (Adults Only)" in service.lower():
        price = 3000.00

    order_id = f"order_{uuid.uuid4()}"

    headers = {
    "Content-Type": "application/json",
    "x-api-version": CASHFREE_API_VERSION,
    "x-client-id": CASHFREE_CLIENT_ID,
    "x-client-secret": CASHFREE_CLIENT_SECRET
}
    payload = {
        "order_id": order_id,
        "order_amount": price,
        "order_currency": "INR",
        "customer_details": {
            "customer_id": str(current_user.id),
            "customer_email": current_user.email,
            "customer_phone": current_user.phone
        },
         "order_meta": {
        "return_url": f"{request.url_root}success?{query}"
    },
    "order_note": f"Appointment for {service}"
}
    try:
        response = requests.post(CASHFREE_API_URL, json=payload, headers=headers)
        print("Cashfree Status Code:", response.status_code)
        print("Cashfree Raw Response:", response.text)

        # This will throw if not 2xx
        response.raise_for_status()

        order_data = response.json()
        return jsonify(order_data)

    except requests.exceptions.HTTPError as http_err:
        print("HTTP error occurred:", http_err)
        if 'response' in locals():
            print("Cashfree Response Body:", response.text)
        return jsonify({"error": str(http_err), "cashfree_response": response.text if 'response' in locals() else "No response"}), 500

    except Exception as e:
        print("General Exception:", e)
        return jsonify({"error": str(e)}), 500
    
from flask import jsonify

@app.route('/cashfree-webhook', methods=['POST'])
def cashfree_webhook():
    """
    Cashfree POSTs payment status updates here.
    This is more reliable than relying on user redirect.
    """
    data = request.get_json()
    print(data)

    if not data:
        return jsonify({"error": "No data received"}), 400

    order_id = data.get("order_id")
    order_status = data.get("order_status")
    customer_id = data.get("customer_details", {}).get("customer_id")
    service = data.get("order_note")  # or parse from metadata
    date_str = data.get("date")       # you must include date in order creation
    time_str = data.get("time")

    if not order_id or not customer_id:
        return jsonify({"error": "Missing order_id or customer_id"}), 400

    if order_status == "PAID":
        user = User.query.get(int(customer_id))
        if user and service and date_str and time_str:
            appt_dt = datetime.fromisoformat(f"{date_str}T{time_str}")
            appt_dt = appt_dt.replace(tzinfo=timezone.utc)

            # Prevent double booking
            existing = Appointment.query.filter_by(
                service=service,
                appointment_date=appt_dt
            ).first()
            if not existing:
                new_appt = Appointment(
                    user_id=user.id,
                    service=service,
                    appointment_date=appt_dt
                )
                db.session.add(new_appt)
                db.session.commit()

    return jsonify({"status": "success"})



@app.route('/success')
@login_required
def success():
    # Get order details from query string
    order_id = request.args.get("order_id")
    order_status = request.args.get("order_status","PAID")  # default to PAID for sandbox testing
    service = request.args.get("service")
    date_str = request.args.get("date")
    time_str = request.args.get("time")

    if not order_id:
        return render_template("cancel.html", error="Order ID missing.")

    if order_status == "PAID":
        if service and date_str and time_str:
            try:
                # Convert appointment date/time to UTC
                appt_dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %I:%M %p")
                appt_dt = appt_dt.replace(tzinfo=timezone.utc)
            except ValueError as e:
                return render_template("cancel.html", error=f"Invalid date/time format: {e}")

            # Check for double booking
            existing = Appointment.query.filter_by(
                service=service,
                appointment_date=appt_dt
            ).first()
            if existing:
                return render_template("cancel.html", error="This time slot is already booked.")

            # Save appointment
            new_appt = Appointment(
                user_id=current_user.id,
                service=service,
                appointment_date=appt_dt
            )
            db.session.add(new_appt)
            db.session.commit()

        return render_template("success.html", order_id=order_id, service=service, date=date_str, time=time_str)

    else:
        # Payment cancelled or failed
        return render_template("cancel.html", order_id=order_id, error="Payment failed or cancelled.")

from pyngrok import ngrok

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
