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
import pytz
from functools import wraps
from flask import jsonify

import markdown
from flask import Markup



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


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        user = User.query.filter_by(api_key=api_key).first()
        if user is None:
            return jsonify({"error": "Invalid or missing API Key"}), 403
        return f(*args, **kwargs, user=user)
    return decorated_function

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    api_key = db.Column(db.String(128), unique=True, nullable=True)
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
    content = TextAreaField('Content')
    post_type = SelectField('Type', choices=[('standard', 'Standard'), ('image', 'Image'), ('quote', 'Quote'), ('link', 'Link'), ('codeblock', 'Code Block')])
    codeblock = TextAreaField('Codeblock')
    quote = TextAreaField('Quote')
    link = StringField('Link')
    image_files = FileField('Upload Images', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg'])], render_kw={"multiple": True})
    tags = StringField('Tags', description="Separate tags with commas")
    is_private = BooleanField('Private Post')
    submit = SubmitField('Post')

    def validate(self, **kwargs):
        # Custom validation logic
        if not super(PostForm, self).validate(**kwargs):
            return False

        if self.post_type.data in ['standard', 'link'] and not self.content.data:
            self.content.errors.append('Content is required for this post type.')
            return False

        if self.post_type.data == 'quote' and not self.quote.data:
            self.quote.errors.append('Quote is required for this post type.')
            return False

        if self.post_type.data == 'codeblock' and not self.codeblock.data:
            self.codeblock.errors.append('Codeblock is required for this post type.')
            return False

        return True


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

# Edit Post Route
@app.route("/post/edit/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)  # Forbidden access if not the author

    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.post_type = form.post_type.data
        post.codeblock = form.codeblock.data
        post.quote = form.quote.data
        post.link = form.link.data
        post.is_private = form.is_private.data

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

        # Tag handling
        if form.tags.data:
            # Clear existing tags and add new ones
            post.tags = []
            tag_names = [t.strip() for t in form.tags.data.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                post.tags.append(tag)

        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))

    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
        form.post_type.data = post.post_type
        form.codeblock.data = post.codeblock
        form.quote.data = post.quote
        form.link.data = post.link
        form.is_private.data = post.is_private
        form.tags.data = ', '.join([tag.name for tag in post.tags])

    return render_template('create_post.html', title='Edit Post', form=form, legend='Edit Post')

@app.route("/post/delete/<int:post_id>", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)

    # Delete related images first
    Image.query.filter_by(post_id=post.id).delete()

    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))



@app.route('/api/create_post', methods=['POST'])
@require_api_key
def create_post_api(user):
    data = request.json

    # Check for minimum data requirements
    if not data or 'post_type' not in data:
        return jsonify({'error': 'Missing post type'}), 400

    # Create a new post instance
    new_post = Post(user_id=user.id, post_type=data['post_type'])

    # Assign fields based on post type
    if data['post_type'] == 'standard':
        if 'content' not in data:
            return jsonify({'error': 'Missing content for standard post'}), 400
        new_post.content = data['content']

    elif data['post_type'] == 'quote':
        if 'quote' not in data:
            return jsonify({'error': 'Missing quote content'}), 400
        new_post.quote = data['quote']

    elif data['post_type'] == 'link':
        if 'link' not in data:
            return jsonify({'error': 'Missing link URL'}), 400
        new_post.link = data['link']

    elif data['post_type'] == 'codeblock':
        if 'codeblock' not in data:
            return jsonify({'error': 'Missing codeblock content'}), 400
        new_post.codeblock = data['codeblock']

    # Add other post type handling as needed

    # Save the post to the database
    db.session.add(new_post)
    db.session.commit()

    return jsonify({'message': 'Post created successfully', 'post_id': new_post.id}), 201



@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    images = Image.query.filter_by(post_id=post.id).all()
    tags = post.tags
    post.content = Markup(markdown.markdown(post.content)) 
    return render_template('post.html', title=post.title, post=post, images=images, tags=tags)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route('/generate_api_key', methods=['POST'])
@login_required
def generate_api_key():
    current_user.api_key = secrets.token_urlsafe(16)
    db.session.commit()
    flash('Your API key has been updated.')
    return redirect(url_for('profile'))



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

    local_timezone = pytz.timezone("Australia/Perth")  # Replace with your timezone, e.g., 'America/New_York'

    for post in posts:
        post.content = Markup(markdown.markdown(post.content))        
        # Convert the post date from UTC to your local timezone
        post.date_posted = post.date_posted.replace(tzinfo=pytz.utc).astimezone(local_timezone)


    return render_template('home.html', title='Home', posts=posts)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

