from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    """This form is used to create or edit a post in the blog."""
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    """This form is used to register a blog user."""
    email = EmailField(name="Email", validators=[DataRequired(), Email()])
    password = PasswordField(name="Password", validators=[DataRequired()])
    name = StringField(name="Name", validators=[DataRequired()])
    submit = SubmitField(label="Sign Me Up!")


class LoginForm(FlaskForm):
    """This form is used to login a blog user."""
    email = EmailField(name="Email", validators=[DataRequired(), Email()])
    password = PasswordField(name="Password", validators=[DataRequired()])
    submit = SubmitField(label="Let Me In!")


class CommentForm(FlaskForm):
    """This form is used to add a comment to a post in the blog."""
    comment_text = CKEditorField(name="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")

