import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

def init_db():
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT 'blue'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
init_db()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()])
    color = SelectField('Color', choices=[
        ('pink', 'Pink'),
        ('purple', 'Purple'),
        ('blue', 'Blue'),
        ('green', 'Green'),
        ('yellow', 'Yellow'),
        ('red', 'Red')
    ], default='blue')
    submit = SubmitField('Save')

def get_db_connection():
    conn = sqlite3.connect('notes.db')
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], password=user_data['password'])
    return None

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                     (form.username.data, hashed_password))
        conn.commit()
        conn.close()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (form.username.data,)).fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            user_obj = User(id=user['id'], username=user['username'], password=user['password'])
            login_user(user_obj, remember=True)
            flash('You have been logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    notes = conn.execute('SELECT * FROM notes').fetchall()
    conn.close()
    return render_template('index.html', notes=notes)

@app.route('/add', methods=('GET', 'POST'))
@login_required
def add_note():
    form = NoteForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        color = form.color.data

        conn = get_db_connection()
        conn.execute('INSERT INTO notes (title, content, color) VALUES (?, ?, ?)',
                     (title, content, color))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('add_note.html', form=form)

@app.route('/<int:id>/edit', methods=('GET', 'POST'))
@login_required
def edit_note(id):
    conn = get_db_connection()
    note = conn.execute('SELECT * FROM notes WHERE id = ?', (id,)).fetchone()
    form = NoteForm(obj=note)

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        color = form.color.data

        conn.execute('UPDATE notes SET title = ?, content = ?, color = ? WHERE id = ?',
                     (title, content, color, id))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    conn.close()
    return render_template('edit_note.html', form=form)

@app.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete_note(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM notes WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
