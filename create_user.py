from app import create_app
from app.extensions import db
from app.models import User
import os

app = create_app()

with app.app_context():
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    role = input("Enter role (admin/analyst): ").strip() or 'analyst'
    
    if User.query.filter_by(username=username).first():
        print(f"⚠️ User '{username}' already exists.")
    else:
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"✅ User '{username}' created successfully!")