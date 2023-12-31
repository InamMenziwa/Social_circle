from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email_field = StringField("Your email", validators=[DataRequired()])
    password = PasswordField("Your password", validators=[DataRequired()])
    name = StringField("Your name", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email_field = StringField("Your email", validators=[DataRequired()])
    password = PasswordField("Your password", validators=[DataRequired()])
    submit = SubmitField("Log in")

class Comment_of_user(FlaskForm):
    comment = CKEditorField("Comment on post", validators=[DataRequired()])
    submit = SubmitField("Post comment")

