from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_migrate import Migrate
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import plotly.graph_objs as go
from datetime import datetime
from urllib.parse import quote

app = Flask(__name__, static_url_path='/static', instance_relative_config=True)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
url = quote("examplestring")

# User model


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    weights = db.relationship('Weight', backref='user', lazy=True)
    goals = db.relationship('Goal', backref='user', lazy=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

# Weight model


class Weight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weight = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Goal model


class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_weight = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration form


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'Email is already in use. Please choose a different one.')

# Login form


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Weight form


class WeightForm(FlaskForm):
    weight = FloatField('Weight', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Goal form


class GoalForm(FlaskForm):
    goal_weight = FloatField('Goal Weight', validators=[DataRequired()])
    submit = SubmitField('Set Goal')


@app.route('/')
@app.route('/index')
@login_required
def index():
    last_weight = None
    progress = 0
    goal_weight = None
    weight_to_go = None

    if current_user.is_authenticated:
        last_entry = Weight.query.filter_by(
            user_id=current_user.id).order_by(Weight.date.desc()).first()
        if last_entry:
            last_weight = last_entry.weight

        goal_entry = Goal.query.filter_by(
            user_id=current_user.id).order_by(Goal.date.desc()).first()
        if goal_entry:
            goal_weight = goal_entry.target_weight
            if last_weight and goal_weight:
                weight_to_go = goal_weight - last_weight
                progress = max(
                    0, min(100, ((goal_weight - last_weight) / goal_weight) * 100))

    return render_template('index.html', last_weight=last_weight, progress=round(progress), weight_to_go=weight_to_go, goal_weight=goal_weight)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/record', methods=['GET', 'POST'])
@login_required
def record():
    form = WeightForm()
    if form.validate_on_submit():
        weight_entry = Weight(weight=form.weight.data, user_id=current_user.id)
        db.session.add(weight_entry)
        db.session.commit()
        flash('Weight recorded successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('record.html', form=form)


@app.route('/set_goal', methods=['GET', 'POST'])
@login_required
def set_goal():
    form = GoalForm()
    if form.validate_on_submit():
        goal_weight = form.goal_weight.data
        new_goal = Goal(target_weight=goal_weight, user_id=current_user.id)
        db.session.add(new_goal)
        db.session.commit()
        flash('Goal weight set successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('set_goal.html', form=form)


@app.route('/summary')
@login_required
def summary():
    summary_data = summarize_bodyweight_entries(current_user.id)
    dates = [entry.date for entry in summary_data['entries']]
    weights = [entry.weight for entry in summary_data['entries']]
    graph = go.Figure(data=go.Scatter(x=dates, y=weights,
                      mode='markers+lines', name='Weight Trend'))
    graph.update_layout(title='Bodyweight Trend',
                        xaxis_title='Date', yaxis_title='Weight (kg)')
    graphJSON = graph.to_json()
    summary_data['graphJSON'] = graphJSON
    return render_template('summary.html', summary=summary_data)


def summarize_bodyweight_entries(user_id):
    entries = Weight.query.filter_by(
        user_id=user_id).order_by(Weight.date).all()
    if not entries:
        return {"total_entries": 0, "average_weight": 0, "min_weight": 0, "max_weight": 0, "entries": []}
    total_weight = sum(entry.weight for entry in entries)
    average_weight = total_weight / len(entries)
    weights = [entry.weight for entry in entries]
    return {
        "total_entries": len(entries),
        "average_weight": average_weight,
        "min_weight": min(weights),
        "max_weight": max(weights),
        "entries": entries
    }


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
