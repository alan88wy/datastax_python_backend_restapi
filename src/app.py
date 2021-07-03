import re

from flask import Flask, json, jsonify, request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import uuid
import os
import requests
import json
from requests.exceptions import HTTPError

from flask_mail import Mail, Message

app = Flask(__name__)

CLIENT_ID=os.environ['CLIENT_ID'] 
CLIENT_SECRET = os.environ['CLIENT_SECRET']
JWT_SECRET = os.environ['JWT_SECRET']
ASTRA_DB_ID=os.environ['ASTRA_DB_ID'] 
ASTRA_DB_REGION=os.environ['ASTRA_DB_REGION'] 
ASTRA_DB_KEYSPACE=os.environ['ASTRA_DB_KEYSPACE'] 
ASTRA_DB_APPLICATION_TOKEN=os.environ['ASTRA_DB_APPLICATION_TOKEN'] 
ASTRA_CLUSTER_ID=os.environ['ASTRA_CLUSTER_ID'] 

app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']   # d41680001cbbea
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']   # 9dd173b4838070
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Setting up REST API

headers = {
    'X-Cassandra-Token': ASTRA_DB_APPLICATION_TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = JWT_SECRET  # Change this!
jwt = JWTManager(app)
mail = Mail(app)

def checkInt(str):
    if str[0] in ('-', '+'):
        return str[1:].isdigit()
    return str.isdigit()

def get_user_by_email(email):
	query = {
		"email": {
			"$eq": [email]
		}
	}
	req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/users?where="
	req_url = req_url + json.dumps(query)

	response = requests.get(req_url, headers=headers)
	response.encoding = 'utf-8' # Optional: requests infers this internally

	if response.status_code == 200 and response.json()['count'] > 0:
		user = response.json()['data'][0]
		return user
	else:
		return None

def get_planet(query):

	req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/planet?where="
	req_url = req_url + json.dumps(query)

	response = requests.get(req_url, headers=headers)
	response.encoding = 'utf-8' # Optional: requests infers this internally

	if response.status_code == 200 and response.json()['count'] > 0:
		planet = response.json()['data'][0]
		return planet
	else:
		return None

@app.route('/')
def hello_world():
    return '<h1>Hello World</h1>', 200


@app.route('/json')
def hello_json():
    return jsonify(message = 'Hello Json'), 200

@app.route('/not_found')
def not_found():
	return jsonify(message='Resource Not Found'), 404

@app.route('/parameters')
def parameters():
	name = request.args.get('name')
	age = request.args.get('age')

	if checkInt(age):
		age = int(age)
	else:
		return jsonify(message = "Sorry " + name + ", age enter is invalid !"), 401

	if age < 18:
		return jsonify(message="Sorry " + name + ", you are not old enough"), 401
	else:
		return jsonify(message="Welcome " + name + ", you are old enough")

@app.route('/url_variables/<string:name>/<int:age>')
def url_variables(name: str, age: int):

	if age < 18:
		return jsonify(message="Sorry " + name + ", you are not old enough"), 401
	else:
		return jsonify(message="Welcome " + name + ", you are old enough")	

@app.route('/planets', methods=['GET'])
def planets():

	req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/planet/rows"
	
	response = requests.get(req_url, headers=headers)
	response.encoding = 'utf-8' # Optional: requests infers this internally

	return jsonify(response.json()['data'])

@app.route('/register', methods=['POST'])
def register():
	email = request.form['email']

	user = get_user_by_email(email)

	if user != None:
			return jsonify(message='That email already exists.'), 404
	else:

		req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/users"

		data = {
			"id": str(uuid.uuid1()),
			"first_name": request.form['first_name'],
			"last_name": request.form['last_name'],
			"password": request.form['password'],
			"email": email		
		}
		
		try:
			response = requests.post(req_url, headers=headers, json=data)
			response.encoding = 'utf-8' # Optional: requests infers this internally
			
			# If the response was successful, no Exception will be raised
			response.raise_for_status()
			
		except HTTPError as http_err:
			return jsonify(message=f'HTTP error occurred: {http_err}')  # Python 3.6
		except Exception as err:
			return jsonify(message=f'Other error occurred: {err}')  # Python 3.6
		else:
			return jsonify(message='User created successfully'), 201

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def login():
	if request.is_json:
		email = request.json['email']
		password = request.json["password"]
    
	else:
		email = request.form['email']
		password = request.form['password']

	user = get_user_by_email(email)

	if user == None:
		return jsonify(message="No such user exist!"), 401
	else:
		if str(user['password']) == str(password):
			access_token = create_access_token(identity=email)
			return jsonify(message='Login Successful!', access_token=access_token)
		else:
			return jsonify(message='Wrong password enter'), 401


@app.route('/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):

	user = get_user_by_email(email)

	if user == None:
		return jsonify(message="That email does not exist!"), 401
	else:
		msg = Message('Your planetary API password is ' + user.password, sender='admin@planetary-api.com', recipients=['email'])
		mail.send(msg)
		return jsonify(message="Password sent to " + email)

@app.route('/update_user', methods=['PUT'])
@jwt_required()  
def update_user():
	email = request.form['email']

	user = get_user_by_email(email)

	if user == None:
			return jsonify(message='That email does not exists.'), 404
	else:

		req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/users/"+str(user['id'])

		data = {
			"first_name": request.form['first_name'],
			"last_name": request.form['last_name'],
			"password": request.form['password']
		}
		
		try:
			response = requests.put(req_url, headers=headers, json=data)
			response.encoding = 'utf-8' # Optional: requests infers this internally
		
			# If the response was successful, no Exception will be raised
			response.raise_for_status()
		
		except HTTPError as http_err:
			return jsonify(message=f'HTTP error occurred: {http_err}')  
		except Exception as err:
			return jsonify(message=f'Other error occurred: {err}')  
		else:
			return jsonify(message='You have updated user ' + request.form['first_name']), 202


@app.route('/planet_details/<string:planet_id>', methods=['GET'])
def planet_details(planet_id:str):

	query = {
		"planet_id": {
			"$eq": [str(planet_id)]
		}
	}

	planet = get_planet(query)

	if planet:
		return jsonify(planet)
	else:
		return jsonify(message='That planet does not exist'), 404

@app.route('/add_planet', methods=['POST'])
@jwt_required()    # Require login using JWT before doing this add_planet
def add_planet():
	planet_name = request.form['planet_name']

	query = {
		"planet_name": {
			"$eq": [str(planet_name)]
		}
	}

	planet = get_planet(query)

	if planet:
		return jsonify('There is already a planet by that name of ' + planet_name), 409
	else:

		req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/planet"	

		data = {
			"planet_id" : str(uuid.uuid1()),
			"planet_name": planet_name,
			"planet_type": request.form['planet_type'],
			"home_star": request.form['home_star'],
			"mass": float(request.form['mass']),
			"radius": float(request.form['radius']),
			"distance": float(request.form['distance'])
		}
		
		try:
			response = requests.post(req_url, headers=headers, json=data)
			response.encoding = 'utf-8' # Optional: requests infers this internally
			
			# If the response was successful, no Exception will be raised
			response.raise_for_status()
			
		except HTTPError as http_err:
			return jsonify(message=f'HTTP error occurred: {http_err}')  # Python 3.6
		except Exception as err:
			return jsonify(message=f'Other error occurred: {err}')  # Python 3.6
		else:
			return jsonify(message='You have added a planet'), 201

@app.route('/update_planet', methods=['PUT'])
@jwt_required()  
def update_planet():
	
	planet_id = request.form['planet_id']
	
	query = {
		"planet_id": {
			"$eq": [str(planet_id)]
		}
	}

	planet = get_planet(query)

	if planet == None:
		return jsonify(message='That planet with planet id of ' + str(planet_id) + ' does not exist !'), 404
	else:

		req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/planet/"	
		req_url = req_url + str(planet_id)

		print(req_url)

		data = {
			"planet_name": request.form['planet_name'],
			"planet_type": request.form['planet_type'],
			"home_star": request.form['home_star'],
			"mass": float(request.form['mass']),
			"radius": float(request.form['radius']),
			"distance": float(request.form['distance'])
		}

		try:
			response = requests.put(req_url, headers=headers, json=data)
			response.encoding = 'utf-8' # Optional: requests infers this internally
			
			# If the response was successful, no Exception will be raised
			response.raise_for_status()
			
		except HTTPError as http_err:
			return jsonify(message=f'HTTP error occurred: {http_err}')  # Python 3.6
		except Exception as err:
			return jsonify(message=f'Other error occurred: {err}')  # Python 3.6
		else:
			return jsonify(message='You have updated planet '+ request.form['planet_name'],), 202

@app.route('/delete_planet/<string:planet_id>', methods=['DELETE'])
@jwt_required()  
def delete_planet(planet_id:str):

	query = {
		"planet_id": {
			"$eq": [str(planet_id)]
		}
	}

	planet = get_planet(query)

	if planet == None:
		return jsonify(message='That planet does not exist !'), 404
	else:

		req_url = f"https://{ASTRA_CLUSTER_ID}-{ASTRA_DB_REGION}.apps.astra.datastax.com/api/rest/v2/keyspaces/awcrm/planet/"	
		req_url = req_url + str(planet_id)

		try:
			response = requests.delete(req_url, headers=headers)
			response.encoding = 'utf-8' # Optional: requests infers this internally
			
			# If the response was successful, no Exception will be raised
			response.raise_for_status()
			
		except HTTPError as http_err:
			return jsonify(message=f'HTTP error occurred: {http_err}')  # Python 3.6
		except Exception as err:
			return jsonify(message=f'Other error occurred: {err}')  # Python 3.6
		else:
			return jsonify(message='You have deleted planet ' + planet['planet_name']), 202

if __name__ == '__main__':
    app.run()
