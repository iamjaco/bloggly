import os
from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, SelectField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime
import os
import secrets
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_login import logout_user


# Flask app and database initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit
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
    posts = db.relationship('Post', backref='author', lazy='dynamic')

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
    images = db.relationship('Image', backref='post', lazy='dynamic')
    tags = db.relationship('Tag', secondary='post_tags', backref=db.backref('posts', lazy='dynamic'))

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}', '{self.post_type}')"

# Image model
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(300), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return f"Image('{self.url}', Post ID: '{self.post_id}')"

# Tag model
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"Tag('{self.name}')"

# Association table for posts and tags
post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

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
    codeblock = TextAreaField('Codeblock')
    quote = TextAreaField('Quote')
    link = StringField('Link')
    image_files = FileField('Upload Images', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg'])], render_kw={"multiple": True})
    tags = StringField('Tags', description="Separate tags with commas")
    is_private = BooleanField('Private Post')
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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data,
                    post_type=form.post_type.data, is_private=form.is_private.data,
                    codeblock=form.codeblock.data, quote=form.quote.data, link=form.link.data,
                    author=current_user)
        db.session.add(post)
        db.session.commit()

        # Image handling
        if form.image_files.data:
            for image_file in request.files.getlist('image_files'):
                random_hex = secrets.token_hex(8)
                _, f_ext = os.path.splitext(secure_filename(image_file.filename))
                unique_filename = random_hex + '_' + datetime.now().strftime("%Y%m%d%H%M%S") + f_ext
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                image_file.save(image_path)
                image_url = os.path.join('images', unique_filename).replace('\\', '/')
                image = Image(url=image_url, post_id=post.id)
                db.session.add(image)
            db.session.commit()

        # Tag handling
        if form.tags.data:
            tag_names = [t.strip() for t in form.tags.data.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                post.tags.append(tag)
            db.session.commit()

        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form)

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    images = Image.query.filter_by(post_id=post.id).all()
    tags = post.tags
    return render_template('post.html', title=post.title, post=post, images=images, tags=tags)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/')
def home():
    if current_user.is_authenticated:
        # Show all public posts and private posts by the logged-in user
        posts = Post.query.filter(
            (Post.is_private == False) | 
            ((Post.is_private == True) & (Post.user_id == current_user.id))
        ).order_by(Post.date_posted.desc()).all()
    else:
        # If not authenticated, show only public posts
        posts = Post.query.filter_by(is_private=False).order_by(Post.date_posted.desc()).all()

    return render_template('home.html', title='Home', posts=posts)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

