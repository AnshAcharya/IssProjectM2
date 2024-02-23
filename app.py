from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, decode_token
import datetime

app = Flask(__name__)
app.static_folder = 'static'
app.secret_key = 'SecurityKeyOfTeanmLAB--4>'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Ansh%402006@127.0.0.1/media_library' 
app.config['DEBUG'] = True
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/', methods=['GET', 'POST'])
def landing_and_login_page():

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username.lower()).first()

        if user:
            stored_password = user.password
            decoded_token = decode_token(stored_password)
            decoded_password = decoded_token['sub']
            if password == decoded_password:
                session['user_id'] = user.user_id
                return redirect('/home')

        return render_template('landing&loginPage.html', message='Invalid username or password')

    return render_template('landing&loginPage.html')

# Route for signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return render_template('signupPage.html', message='Username already exists')

        password_token = create_access_token(identity=password, expires_delta=datetime.timedelta(days=1))  # Expires in 1 day

        try:
            new_user = User(username=username, email=email, password=password_token)
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(f"Error occurred while querying the database: {str(e)}")
            return render_template('signupPage.html', message='Error occurred while creating user')

        session['user_id'] = new_user.user_id
        return redirect('/')

    return render_template('signupPage.html')

# Route for home page
@app.route('/home')
def home():
    return render_template('homePage.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
