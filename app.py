from flask import Flask, render_template, url_for, redirect, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__)

app.config['SECRET_KEY'] = "mysecretkey"


class RegistrationForm(FlaskForm):
    email = StringField('メールアドレス', validators=[
                        DataRequired(), Email(message='正しいメールアドレスを入力してください')])
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[
                             DataRequired(), EqualTo('pass_confirm', message='パスワードが一致していません')])
    pass_confirm = PasswordField('パスワード（確認）', validators=[DataRequired()])
    submit = SubmitField('登録')


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        session["email"] = form.email.data
        session["username"] = form.username.data
        session["password"] = form.password.data
        flash('ユーザーが登録されました')
        return redirect(url_for("user_maintenance"))
    return render_template("register.html", form=form)


@app.route("/user_maintenance")
def user_maintenance():
    return render_template("user_maintenance.html")


if __name__ == "__main__":
    app.run(debug=True)
