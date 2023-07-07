from functools import wraps
import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user as logu, LoginManager, login_required, current_user, logout_user as logou
from forms import CreatePostForm, RegisterForm, LoginForm, Comment_of_user
from flask_gravatar import Gravatar


# Load environment variables from a .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://dbase_2wtb_user:TaHsBegFUwbQsrszMFIqqrLhDnVEvZGX@dpg-cii4p45gkuvojjeifte0-a.oregon-postgres.render.com/dbase_2wtb"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(id)

##CONFIGURE TABLES
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if User.query.filter_by(email=form.email_field.data).first():
        # Send flash messsage
        flash("You've already signed up with that email, log in instead!")
        # Redirect to /login route.
        return redirect(url_for('login'))
    if request.method == "POST" and form.validate_on_submit():
        password = generate_password_hash(
            request.form["password"],
            method='pbkdf2:sha256',
            salt_length=8
        )
        he_is_him = User(name=request.form["name"], email=request.form["email_field"], password=password)
        db.session.add(he_is_him)
        db.session.commit()
        logu(he_is_him)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit() and request.method == "POST":
        email = request.form["email_field"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
                logu(user)
                return redirect(url_for("get_all_posts"))
        else:
            flash("Either the User is incorrect or the password is incorrect")
    return render_template("login.html", form=form)

@app.route("/delete_comment", methods=["GET", "POST"])
def delete_com():
    com_id = request.args.get("id")
    blog_id = request.args.get("post_id")
    commer = Comment.query.filter_by(id=com_id).first()

    if request.method == "POST":
        if commer:
            db.session.delete(commer)
            db.session.commit()
            return redirect(url_for("show_post", post_id=blog_id))  # Redirect after successful deletion
        else:
            # Handle the case where the comment with the given ID was not found
            flash("Comment not found")
            return redirect(url_for("show_post", post_id=blog_id))

    return redirect(url_for("show_post", post_id=blog_id))
@app.route('/logout')
def logout():
    logou()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = Comment_of_user()
    requested_post = BlogPost.query.get(post_id)
    if request.method == "POST" and form.validate_on_submit():
        if current_user.is_authenticated:
            him = Comment(text=request.form.get("comment"),
            comment_author=current_user,
            parent_post=requested_post)
            db.session.add(him)
            db.session.commit()
        else:
            flash("Please log in to comment")
            return redirect(url_for("login"))
    elif request.method == "GET":
        return render_template("post.html", post=requested_post, form=form)
    return render_template("post.html", post=requested_post, form=form)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.before_request
def blog_checker():
    if request.endpoint == 'edit_post':
        post_id = request.view_args.get('post_id')
        post = BlogPost.query.get(post_id)
        if current_user.name != post.author.name:
            flash("This is not your blog post")
            return redirect(url_for("show_post", post_id=post_id))

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)
