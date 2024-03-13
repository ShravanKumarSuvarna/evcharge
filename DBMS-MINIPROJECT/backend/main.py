import json
from flask import Flask, redirect, render_template, flash,request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, logout_user, login_user, LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from flask.globals import request
from flask.helpers import url_for
from werkzeug.exceptions import BadRequest
from flask_login import current_user
from datetime import datetime

with open('config.json','r') as admin_data:
    params=json.load(admin_data)["params"]


# my db connection
local_server = True
app = Flask(__name__)
app.secret_key = "ganesh"

# unique user access
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Connection
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://root:@localhost/evchargingstation'
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))


# defining user table
class User(UserMixin,db.Model):
    User_id = db.Column(db.String(20), primary_key=True)
    User_name = db.Column(db.String(50))
    User_password = db.Column(db.String(1000))

    def get_id(self):
        return self.User_id


#definig charging station table 
class charging_station(db.Model):
    CS_id = db.Column(db.String(20), primary_key=True)
    C_Name = db.Column(db.String(100))
    C_location = db.Column(db.String(500))
    C_Capacity = db.Column(db.Integer)
    C_Status = db.Column(db.String(50))
    C_geolocation = db.Column(db.String(1000))

class maintenance(db.Model):
    maint_id = db.Column(db.String(20), primary_key=True)
    date = db.Column(db.Date, nullable=False)
    Description = db.Column(db.String(1000), nullable=False)
    CS_id = db.Column(db.String(20), db.ForeignKey('charging_station.CS_id'), nullable=False)


class vehicle(db.Model):

    regno = db.Column(db.String(20), primary_key=True)
    vname = db.Column(db.String(100), nullable=False)
    vtype = db.Column(db.String(50), nullable=False)
    batterycapacity = db.Column(db.Integer, nullable=False)
    User_id = db.Column(db.Integer, db.ForeignKey('User.Users_id'))


class Feedback(db.Model):

    f_id = db.Column(db.String(20), primary_key=True)
    comments = db.Column(db.String(500), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    User_id = db.Column(db.String(20), db.ForeignKey('User.Users_id'))
    CS_id = db.Column(db.String(20),db.ForeignKey('charging_station.CS_id'))

class reservation1(db.Model):
    r_id = db.Column(db.String(20), primary_key=True)
    starttime = db.Column(db.Time, nullable=False, default='CURRENT_TIME')
    endtime = db.Column(db.Time, nullable=False, default='CURRENT_TIME')
    CS_id = db.Column(db.String(20), db.ForeignKey('charging_station.CS_id'))
    regno = db.Column(db.String(20), db.ForeignKey('vehicle.regno'))
    User_id = db.Column(db.String(20), db.ForeignKey('User.Users_id'))




@app.route("/")
def home():
   
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("bootstrap2.html")

@app.route("/test")
def test():
    try:
        a = Test.query.all()
        print(a)
        return 'My db connected'
    except Exception as e:
        print(e)
        return 'my db not connected'
#logic for user logout   
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout Successful','warning')
    return redirect(url_for('login'))



#sign up logic
@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        User_id = request.form.get('User_id')  # reading inputs
        User_name = request.form.get('User_name')
        User_password = request.form.get('User_password')

        # check if the User_id already exists in the database
        existing_user = db.session.execute(text("SELECT * FROM User WHERE User_id = :User_id"), {"User_id": User_id}).fetchone()
        if existing_user:
            flash('User_id already taken. Please choose another one.','warning')
            return render_template('usersignup.html')
        encpassword = generate_password_hash(User_password)
        db.session.execute(text("INSERT INTO User (User_id, User_name, User_password) VALUES (:User_id, :User_name, :User_password)"),
                            {"User_id": User_id, "User_name": User_name, "User_password": encpassword})
        db.session.commit()
        user1 = User.query.filter_by(User_id=User_id).first()
        if  user1 and check_password_hash(user1.User_password, User_password):
            login_user(user1)
            flash('Sign in successfull','success')
            return render_template('index.html')

    return render_template("usersignup.html")


#login logic

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        User_id = request.form.get('User_id')
        User_password = request.form.get('User_password')

        # Query the database to get the user with the given User_id
        user = User.query.filter_by(User_id=User_id).first()
        #print(user)
        # If the user does not exist or the passworSd is incorrect, return an error message
        if  user and check_password_hash(user.User_password, User_password):
            login_user(user)
            flash('Logged in successfully','message')
    
            return render_template('index.html')
        
        else:
            flash('Invalid username or password. Please try again.',"danger")
            return render_template("userlogin.html")

        # If the user exists and the password is correct, log in the user
        
    return render_template("userlogin.html",)


@app.route("/addveh",methods=['POST', 'GET'])
def aadveh():
    if request.method == 'POST':
        regno = request.form.get('regno')
        vname = request.form.get('vname')
        vtype = request.form.get('vtype')
        batterycapacity = request.form.get('batterycapacity') 
        User_id=current_user.User_id   # reading inputs

        existing_reg = db.session.execute(text("SELECT * FROM vehicle WHERE regno = :regno"), {"regno": regno}).fetchone()
        if existing_reg:
            flash('REGNO already taken. Please choose another one.','warning')
            return render_template('addveh.html')

        db.session.execute(text("INSERT INTO vehicle (regno,vname,vtype,batterycapacity,User_id) VALUES (:regno,:vname,:vtype,:batterycapacity,:User_id)"),
                            {"regno": regno, "vname": vname, "vtype":vtype,"batterycapacity":batterycapacity,"User_id":User_id})
        db.session.commit()
        flash("Vehicle Added",'info')
        return render_template('addveh.html')
    return render_template('addveh.html')


@app.route('/viewvehicles')
@login_required
def viewvehicles():
    # Assuming you have a Vehicle table with a foreign key 'User_id' linking it to the 'User' table
    query = """
        SELECT * 
        FROM Vehicle 
        WHERE User_id = :user_id
    """
    vehicles = db.session.execute(text(query), {"user_id": current_user.User_id}).fetchall()

    return render_template('viewvehicles.html', vehicles=vehicles)


@app.route('/updatevehicle/<id>', methods=['GET', 'POST'])
@login_required
def updatevehicle(id):
    vehicles = vehicle.query.get_or_404(id)
    if request.method == 'POST':
        vname = request.form['vname']
        vtype = request.form['vtype']
        batterycapacity = request.form['batterycapacity']
        ids=current_user.User_id
        # Update the vehicle record in the database using raw SQL query
        query = """
            UPDATE vehicle 
            SET vname = :vname, vtype = :vtype, batterycapacity = :batterycapacity
            WHERE User_id = :ids AND regno = :id
        """
        db.session.execute(text(query), {'vname': vname, 'vtype': vtype, 'batterycapacity': batterycapacity, 'ids': ids,"id":id})
        db.session.commit()
        
        flash('Vehicle updated successfully.', 'success')
        return redirect(url_for('viewvehicles'))
    
    
    return render_template('updatevehicle.html', vehicle=vehicles)

@app.route('/deletevehicle/<id>', methods=['POST'])
@login_required
def deletevehicle(id):
    # Delete the vehicle record from the database using raw SQL query
    query = "DELETE FROM vehicle WHERE regno = :id"
    result = db.session.execute(text(query), {'id': id})
    db.session.commit()

    # Check if the vehicle was successfully deleted
    if result.rowcount == 0:
        flash('Vehicle not found.', 'error')
    else:
        flash('Vehicle deleted successfully.', 'success')
    
    return redirect(url_for('viewvehicles'))

@app.route("/addfeedback", methods=['POST', 'GET'])
def add_feedback():
    if request.method == 'POST':
        f_id = request.form.get('f_id')
        comments = request.form.get('comments')
        rating = int(request.form.get('rating'))
        User_id = current_user.User_id
        CS_id = request.form.get('CS_id')

        # Check if the provided f_id already exists

        # Check if the provided CS_id is valid
        existing_CS_id = db.session.execute(
            text("SELECT CS_id FROM charging_station WHERE CS_id = :CS_id"),
            {"CS_id": CS_id}
        ).fetchone()
        if not existing_CS_id:
            flash("Invalid CS ID. Please provide a valid CS ID.", 'warning')
            return redirect(url_for('add_feedback'))
        
        existing_fid = db.session.execute( text("SELECT f_id FROM feedback WHERE f_id = :f_id"),
            {"f_id": f_id}).fetchone()
        if existing_fid:
            flash('f_id already taken. Please choose another one.','warning')
            return redirect(url_for('add_feedback'))

        if not existing_CS_id:
            flash("Invalid CS ID. Please provide a valid CS ID.", "error")
            return redirect(url_for('add_feedback'))

        # Insert the feedback into the database
        db.session.execute(
            text("INSERT INTO feedback (f_id, comments, rating, User_id, CS_id) VALUES (:f_id, :comments, :rating, :User_id, :CS_id)"),
            {"f_id": f_id, "comments": comments, "rating": rating, "User_id": User_id, "CS_id": CS_id}
        )
        db.session.commit()
        flash("Feedback added successfully.", "info")
        return redirect(url_for('add_feedback'))
    
    return render_template('addfeedback.html')



@app.route('/viewfeedback')
@login_required
def view_feedback():
    # Fetch feedback for the current user
    query = """
        SELECT * 
        FROM feedback 
        WHERE User_id = :user_id
    """
    feedbacks = db.session.execute(text(query), {"user_id": current_user.User_id}).fetchall()

    return render_template('viewfeedback.html', feedbacks=feedbacks)

#####3

@app.route("/addreservation", methods=['POST', 'GET'])
def addreservation():
    if request.method == 'POST':
        r_id = request.form.get('r_id')
        starttime = request.form.get('starttime')
        # Here, you need to provide a valid value for endtime
        endtime = request.form.get('endtime')  # Replace this with a valid value
        CS_id = request.form.get('CS_id')
        regno = request.form.get('regno')
        User_id = current_user.User_id

        existing_CS_id = db.session.execute(
            text("SELECT CS_id FROM charging_station WHERE CS_id = :CS_id"),
            {"CS_id": CS_id}
        ).fetchone()
        if not existing_CS_id:
            flash("Invalid CS ID. Please provide a valid CS ID.", 'warning')
            return redirect(url_for('addreservation'))
        
        existing_regno=db.session.execute(
            text("SELECT regno FROM vehicle WHERE regno = :regno"),{'regno': regno}
        ).fetchone()
        if not existing_regno:
            flash("Invalid Regno. Please provide a valid Regno.", 'warning')
            return redirect(url_for('addreservation'))


        existing_rid = db.session.execute( text("SELECT r_id FROM reservation1 WHERE r_id = :r_id"),
            {"r_id": r_id}).fetchone()
        if existing_rid:
            flash('r_id already taken. Please choose another one.','warning')
            return redirect(url_for('addreservation'))

        if not existing_CS_id:
            flash("Invalid CS ID. Please provide a valid CS ID.", "error")
            return redirect(url_for('addreservation'))

        # Insert the reservation into the database
        db.session.execute(
            text("INSERT INTO reservation1 (r_id, starttime, endtime, CS_id, regno, User_id ) VALUES (:r_id, :starttime, :endtime, :CS_id, :regno, :User_id)"),
            {"r_id": r_id, "starttime": starttime, "endtime": endtime, "CS_id": CS_id, "regno": regno, "User_id": User_id}
        )
        db.session.commit()
        flash("Reserved successfully.", "info")
        return redirect(url_for('addreservation'))

    return render_template('addreservation.html')



@app.route('/viewreservation')
@login_required
def viewreservation():
    # Fetch feedback for the current user
    query = """
        SELECT * 
        FROM reservation1 
        WHERE User_id = :user_id
    """
    reserv = db.session.execute(text(query), {"user_id": current_user.User_id}).fetchall()

    return render_template('viewreservation.html', reserv=reserv)


@app.route('/updatereservation/<id>', methods=['GET', 'POST'])
@login_required
def updatereservation(id):
    reservation = reservation1.query.get_or_404(id)
    if request.method == 'POST':
        starttime = request.form['starttime']
        endtime = request.form['endtime']
        regno = request.form['regno']
        CS_id = request.form['CS_id']
        ids=current_user.User_id
        # Update the vehicle record in the database using raw SQL query
        query = """
            UPDATE  reservation1
            SET starttime = :starttime,endtime = :endtime, regno = :regno, CS_id = :CS_id
            WHERE User_id = :ids AND r_id =:id
        """
        db.session.execute(text(query), {'starttime':starttime,'endtime' :endtime, 'regno' :regno, 'CS_id' :CS_id, 'ids': ids,'id':id})
        db.session.commit()
        
        flash('Reservation updated successfully.', 'success')
        return redirect(url_for('viewreservation'))
    
    
    return render_template('updatereservation.html', reservation=reservation)

@app.route('/deletereservation/<id>', methods=['POST'])
@login_required
def deletereservation(id):
    # Delete the vehicle record from the database using raw SQL query
    query = "DELETE FROM reservation1 WHERE r_id = :id"
    result = db.session.execute(text(query), {'id': id})
    db.session.commit()

    # Check if the vehicle was successfully deleted
    if result.rowcount == 0:
        flash('Reservation not found.', 'error')
    else:
        flash('Reservation deleted successfully.', 'success')
    
    return redirect(url_for('viewreservation'))



#admin login Logic
@app.route("/admin", methods=['POST', 'GET'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if(username==params['username'] and password==params['password']):
            session['user']=username
            flash('Login successsful','info')
            return render_template("dashboard.html")
        else:
            flash('Invalid username or password. Please try again.',"danger")   

        
        
    return render_template("admin.html")


@app.route('/logoutadmin')
def logoutadmin():
    session.pop('user')
    flash('Your are logedout Admin','primary')
    return redirect(url_for('admin'))

@app.route('/addcharger',methods=['POST', 'GET'])
def addcharger():
    if request.method == 'POST':
        CS_id = request.form.get('CS_id')  # reading inputs
        C_Name = request.form.get('C_Name')
        C_location = request.form.get('C_location')
        C_Capacity = request.form.get('C_Capacity')  # reading inputs
        C_Status = request.form.get('C_Status')
        C_geolocation = request.form.get('C_geolocation')

        existing_csid = db.session.execute(text("SELECT * FROM charging_station WHERE CS_id = :CS_id"), {"CS_id": CS_id}).fetchone()
        if existing_csid:
            flash('CS_id already taken. Please choose another one.','warning')
            return render_template('addcharger.html')
        
        db.session.execute(text("INSERT INTO charging_station (CS_id,C_Name,C_location,C_Capacity,C_Status,C_geolocation) VALUES (:CS_id,:C_Name,:C_location,:C_Capacity,:C_Status,:C_geolocation)"),
                            {"CS_id": CS_id, "C_Name": C_Name, "C_location": C_location,"C_Capacity":C_Capacity,"C_Status":C_Status,"C_geolocation":C_geolocation})
        db.session.commit()
        flash("Charging station Added",'info')
    return render_template('addcharger.html')

@app.route('/viewcharger')
def viewcharger():
    charging_stations = db.session.query(charging_station).all()
    return render_template('viewcharger.html', charging_stations=charging_stations)

@app.route("/updatecharger/<id>", methods=["GET", "POST"])
def updatecharger(id):
    charger = charging_station.query.get_or_404(id)
    if request.method == "POST":
        charger.C_Name = request.form["C_Name"]
        charger.C_location = request.form["C_location"]
        charger.C_Capacity = request.form["C_Capacity"]
        charger.C_Status = request.form["C_Status"]
        db.session.commit()
        flash("Charging station updated successfully", "success")
        return redirect(url_for("viewcharger"))
    return render_template("updatecharger.html", charging_station=charger)

@app.route("/deletecharger/<id>", methods=["POST"])
def deletecharger(id):
    try:
        id = id
    except ValueError:
        raise BadRequest("Invalid ID")

    charging_station_instance = charging_station.query.get_or_404(id)
    db.session.delete(charging_station_instance)
    db.session.commit()
    flash("Charging station deleted successfully", "success")
    return redirect(url_for("viewcharger"))


@app.route('/addmaintenance', methods=['GET', 'POST'])
def add_maintenance():
    if request.method == 'POST':
        maint_id = request.form.get('maint_id')  # reading inputs
        date = request.form.get('date')
        Description = request.form.get('Description')
        CS_id = request.form.get('CS_id')

        existing_msid = db.session.execute(text("SELECT * FROM maintenance WHERE maint_id = :maint_id"), {"maint_id": maint_id}).fetchone()
        if existing_msid:
            flash('Maint_id already taken. Please choose another one.','warning')
            return render_template('addmaintenance.html')
        
        existing_csid = db.session.execute(text("SELECT * FROM charging_station WHERE CS_id = :CS_id"), {"CS_id": CS_id}).fetchone()
        if not existing_csid:
            flash('CS_id is invalid.','warning')
            return render_template('addmaintenance.html')
        
        db.session.execute(text("INSERT INTO maintenance (maint_id,date,Description,CS_id) VALUES (:maint_id,:date,:Description,:CS_id)"),
                            { "maint_id":maint_id, "date": date,"Description":Description,"CS_id": CS_id})
        db.session.commit()
        flash("Maintenance Added",'info')
    return render_template('addmaintenance.html')

@app.route('/viewmaintenance')
def viewmaintenance():
    maintain = db.session.query(maintenance).all()
    return render_template('viewmaintenance.html', maintain=maintain)

@app.route("/updatemaintenance/<id>", methods=["GET", "POST"])
def updatemaintenance(id):
    mains = maintenance.query.get_or_404(id)
    if request.method == "POST":
        mains.date = request.form["date"]
        mains.Description = request.form["Description"]
        db.session.commit()
        flash("Maintenance updated successfully", "success")
        return redirect(url_for("viewmaintenance"))
    
    
    return render_template("updatemaintenance.html", maintain=mains)

@app.route("/deletemaintenance/<id>", methods=["POST"])
def deletemaintenance(id):
    try:
        id = id
    except ValueError:
        raise BadRequest("Invalid ID")

    instance = maintenance.query.get_or_404(id)
    db.session.delete(instance)
    db.session.commit()
    flash("Maintenance deleted successfully", "success")
    return redirect(url_for("viewmaintenance"))

@app.route('/viewfeedbackd')
def viewfeedbackd():
    # Fetch feedback for the current user
    query = """
        SELECT * 
        FROM feedback 
        
    """
    feedbacks = db.session.execute(text(query)).fetchall()

    return render_template('viewfeedbackd.html', feedbacks=feedbacks)

@app.route('/viewreservationd')
def viewreservationd():
    # Fetch feedback for the current user
    query = """
        SELECT * 
        FROM reservation1 
        
    """
    reserv = db.session.execute(text(query)).fetchall()

    return render_template('viewreservationd.html', reserv=reserv)

@app.route('/viewuser')
def viewuser():
    # Fetch feedback for the current user
    query = """
        SELECT * 
        FROM user 
        
    """
    userss = db.session.execute(text(query)).fetchall()

    return render_template('viewuser.html', userss=userss)

if __name__ == "__main__":
    app.run(debug=True)
