
__author__ = 'Dell'
from flask import Flask, render_template ,flash ,redirect ,url_for , session ,request,logging
from data import Articles
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
from flask_login import current_user ,login_required
from wtforms import StringField, PasswordField, SubmitField, SelectField,TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email, Optional
from functools import wraps
from datetime import datetime
from flask_wtf.file import FileField,FileAllowed



app = Flask(__name__)
app.config['SECRET_KEY'] = 'top-secret'


#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'pspr123'
app.config['MYSQL_DB'] = 'mydatabase'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = 'asdsaafsfasfa'

#init MYSQL
mysql = MySQL(app)

Articles = Articles()

@app.route('/users')
def users():
    cur = mysql.connection.cursor()
    cur.execute('''SELECT * FROM user''')
    rv =cur.fetchall()
    return str(rv)

@app.route('/admin')
def admin():
    return render_template('admin.html')

#Index
@app.route("/")
def index():
    return render_template("layout.html")

#About
@app.route('/about')
def about():
    return render_template('about.html')

#Articles
@app.route('/articles')
def articles():
    return render_template('articles.html',articles = Articles)

#Single Article
@app.route('/article/<string:id>')
def article(id):
    return render_template('article.html',id = id)

#Register Form Class
class RegisterForm(FlaskForm):
    firstname = StringField("First Name", validators=[DataRequired(), Length(min=1 ,max=30)])
    lastname = StringField("Last Name", validators=[DataRequired(),Length(min=1 ,max=30)])
    address = StringField("Address", validators=[DataRequired(), Length(min=1 ,max=30)])
    phone = StringField("Phone", validators=[DataRequired()])
    email =StringField('Email', validators=[Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4 ,max=25)])
    user_type = SelectField('User Type', default="user", choices=[('admin', 'admin'), ('user', 'user')])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


# class Post(FlaskForm):
#     title =StringField('title',validators=[DataRequired()])
#     date_posted = StringField('title',validators=[DataRequired(default=datetime.utcnow)])
#     content = StringField('content',validators=[DataRequired()])
#
#     def __repr__(self):
#         return "Post('{self.title}','{self.date_posted}')"


# #Update Account
# class UpdateAccountForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired(), Length(min=4 ,max=25)])
#     email =StringField('Email', validators=[DataRequired(), Email()])
#     picture = FileField('Update Profile', validators=[FileAllowed(['jpg','png'])])
#     submit = SubmitField('Update')
#
#     def validate_username(self,username):
#         if username.data != current_user.username:
#             user = User.query.filter_by(username=username.data).first()
#             if user:
#                 raise ValidationError('This username is taken already.Please choose an other one')
#
#     def validate_email(self,email):
#         if email.data != current_user.email:
#             user = User.query.filter_by(email=email.data).first()
#             if user:
#                 raise ValidationError('This email address is taken already.Please choose for an other one')
#User Register
@app.route('/register',methods =['GET','POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        first_name =form.firstname.data
        last_name = form.lastname.data
        phone = form.phone.data
        address =form.address.data
        email = form.email.data
        username = form.username.data
        user_type = form.user_type.data
        password = form.password.data
        password_hashed = sha256_crypt.encrypt(str(password))
        #create cursor
        # flash('{}\n{}\n{}\n{}\n{}\n{}\n{}'.format(first_name, last_name, phone, address, email, username, password_hashed))

        cur = mysql.connection.cursor()

        sql = """INSERT INTO user (firstname, lastname, address ,phone, username, user_type, password, email) VALUES(%s,%s ,%s ,%s , %s, %s ,%s ,%s)"""
        val = (first_name, last_name, address, phone,username , user_type, password_hashed, email)
        #Executive cursor querylastname
        cur.execute(sql, val)

        #commit to DB
        try:
            mysql.connection.commit()
            flash('You are successfully registered and can log in','success')
        except MySQL:
            flash('Error adding to the database', 'danger')

        return redirect(url_for('login'))
    else:
        form.password.data=''
        form.email.data=''
        form.username.data=''

    return render_template('register.html',form=form)

#user login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        user_type = request.form['user_type']

        #create cursor
        cur = mysql.connection.cursor()

        #Get uer by username
        result = cur.execute('SELECT * FROM user WHERE username = %s', [username])

        #if  == "admin":
            #return redirect(url_for('admin.html'))
        if result > 0:
            #Get stored hash
            data = cur.fetchone()
            password = data['password']

            #compare Passwords
            if sha256_crypt.verify(password_candidate , password):
                session['logged_in'] = True
                session['username'] = username
                session['id'] = data['id']

                flash('You are now logged in','success')
                #close connection
                cur.close()
                return redirect(url_for('account'))
            else:
                error = 'Invalid login'
                flash(error)
    else:
        error = 'Username not found'
        flash(error)

    return render_template('logging.html')

#Check if user logged in
def is_logged_in(f):
    def wrap (*args, **kwargs):
        if session['logged_in' ]:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized, please login','danger')
            return redirect(url_for('login'))
        return wrap()

#Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('login'))

# #Profile Account
# @app.route('/account',methods=['GET','POST'])
# # @login_required
# def account():
#     form = UpdateAccountForm()
#     if form.validata_on_submit():
#         current_user.username = form.username.data
#         current_user.email = form.email.data
#         mysql.session.commit()
#         flash('Your account has been updated!','success')
#         return redirect(url_for('account'))
#     elif request.method == 'GET':
#         form.username.data = current_user.username
#         form.email.data = current_user.email
#     image_file = url_for('static',filename='profile_pics/' + current_user.image_file)
#     return render_template('account.html',title='Account',
#                            image_file=image_file ,form=form)
@app.route('/account',methods=['GET','POST'])
def account():
    # Check if user is loggedin
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    else:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM user WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        # Show the profile page with account info
    return render_template('account.html', title ='Account', account=account)


if __name__ == "__main__":
    app.run(debug=True)