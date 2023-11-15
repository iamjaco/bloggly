from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired


# Flask app and database initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# Flask-Login initialization
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_type = db.Column(db.String(20), nullable=False, default='standard')
    codeblock = db.Column(db.Text)
    quote = db.Column(db.Text)
    link = db.Column(db.String(300))
    sentiment = db.Column(db.String(50))
    is_pinned = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}', '{self.post_type}')"


# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose a different one.')

# Login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class PostForm(FlaskForm):
    title = StringField('Title')
    content = TextAreaField('Content', validators=[DataRequired()])
    post_type = SelectField('Type', choices=[('standard', 'Standard'), ('image', 'Image'), ('quote', 'Quote'), ('link', 'Link'), ('codeblock', 'Code Block')])
    submit = SubmitField('Post')


# Registration route
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# Login route
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, post_type=form.post_type.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form)


@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


# Home route
@app.route('/')
@login_required
def home():
    # Dummy posts data
    posts = [
        {
            'title': '',
            'content': 'This is the content of the first post.',
            'date_posted': datetime(2023, 3, 15, 10, 30),
            'post_type': 'standard',
            'codeblock': None,
            'quote': None,
            'link': None,
            'images': []
        },
        {
            'title': 'pretty pics',
            'content': '',
            'date_posted': datetime(2023, 3, 16, 11, 45),
            'post_type': 'image',
            'codeblock': None,
            'quote': None,
            'link': None,
            'images': [{'url': 'https://via.placeholder.com/600x400'}, {'url': 'https://via.placeholder.com/600x400'}]
        },
        {
            'title': '',
            'content': '',
            'date_posted': datetime(2023, 3, 17, 12, 0),
            'post_type': 'quote',
            'codeblock': None,
            'quote': '“The only impossible journey is the one you never begin.” – Tony Robbins',
            'link': None,
            'images': []
        },
        {
            'title': '',
            'content': '',
            'date_posted': datetime(2023, 3, 18, 8, 20),
            'post_type': 'link',
            'codeblock': None,
            'quote': None,
            'link': 'https://example.com',
            'images': []
        },
        {
            'title': '',
            'content': '',
            'date_posted': datetime(2023, 3, 19, 9, 15),
            'post_type': 'codeblock',
            'codeblock': 'print("Hello, World!")',
            'quote': None,
            'link': None,
            'images': []
        },
        {
            'title': '',
            'content': '',
            'date_posted': datetime(2023, 3, 20, 14, 30),
            'post_type': 'image',
            'codeblock': None,
            'quote': None,
            'link': None,
            'images': [{'url': 'https://via.placeholder.com/600x400'}]  # Single image
        }
    ]

    return render_template('home.html', title='Home', posts=posts)

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
