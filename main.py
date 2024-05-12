from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['Post', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2', salt_length=8)
        name = request.form['name']
        user = User(email=email, password=hashed_password, name=name)
        # CREATE RECORD in sql lite
        with app.app_context():
            db.session.add(user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(user)

            # Can redirect() and get name from the current_user

            return redirect(url_for('secrets', name=request.form.get('name')))

    return render_template("register.html")


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        plain_password = request.form['password']
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, plain_password):
            # login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash('Check email or password')

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    name = request.args.get('name')
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    # send_from_directory used to download the files
    return send_from_directory('static', 'files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True, port=8787)
