from app1 import db, app, User, Appointment

with app.app_context():
    db.create_all()
    print("Database tables created successfully!")