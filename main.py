from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)
login_manager = LoginManager()
login_manager.init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL_1", "sqlite:///blog.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    """A Parent table to both the 'BlogPost' and 'Comment' tables in the database.
    It has a bidirectional one-to-many relationship with each of its child tables."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    """A child table of the 'User' table.
    A parent table to the 'Comment' table in the database, having a bidirectional one-to-many relationship with it."""
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    post_comments = relationship("Comment", back_populates="blog_post")


class Comment(db.Model):
    """This is a child table to each of the 'User' and 'Comment' tables in the database."""
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="post_comments")

    text = db.Column(db.Text, nullable=False)


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    user_object = User.query.get(int(user_id))
    return user_object


def admin_only(the_function):
    @wraps(the_function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return the_function(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, the_current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("That email has already been used to sign up. Login instead.")
            return redirect(url_for("login"))
        hash_and_salted_password = generate_password_hash(
            password=register_form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            email=register_form.email.data,
            password=hash_and_salted_password,
            name=register_form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, the_current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        input_email = login_form.email.data
        input_password = login_form.password.data
        required_user = User.query.filter_by(email=input_email).first()
        if required_user and check_password_hash(pwhash=required_user.password, password=input_password):
            login_user(required_user)
            return redirect(url_for("get_all_posts"))
        elif not required_user:
            flash("That email is not linked to any user account in our database. Please try again or register.")
            return redirect(url_for("login"))
        elif not check_password_hash(pwhash=required_user.password, password=input_password):
            flash("You have typed an incorrect password. Please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form=login_form, the_current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You cannot add a comment until you are logged in. Please login or register to comment on this post.")
            return redirect(url_for("login"))
        new_comment = Comment(
            author_id=current_user.id,
            blog_post_id=post_id,
            text=comment_form.comment_text.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post"))
    return render_template("post.html", post=requested_post, form=comment_form, the_current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", the_current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", the_current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    add_post_form = CreatePostForm()
    if add_post_form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            title=add_post_form.title.data,
            subtitle=add_post_form.subtitle.data,
            body=add_post_form.body.data,
            img_url=add_post_form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=add_post_form, the_current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_post_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_post_form.validate_on_submit():
        post.title = edit_post_form.title.data
        post.subtitle = edit_post_form.subtitle.data
        post.img_url = edit_post_form.img_url.data
        post.body = edit_post_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", is_edit=True, form=edit_post_form, the_current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)