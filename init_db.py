from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # db.drop_all()
    db.create_all()

    password = "123"
    password_hash = generate_password_hash(password)
    user1 = User(email="admin_user@test.com", username="Admin User",
                password_hash=password_hash, administrator="1")
    db.session.add(user1)
    db.session.commit()


