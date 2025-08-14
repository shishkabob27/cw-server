import hashlib
import json
import random
import shutil
import threading
import time
import uuid
from flask import Flask, render_template, make_response, jsonify, request, redirect, url_for, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
import argparse
from urllib.parse import parse_qs
from collections import deque
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=5000)
parser.add_argument('--debug', action='store_true')

args, _ = parser.parse_known_args()

def GetOrCreateSecret():
	os.makedirs("data/persist", exist_ok=True)
	secret = "data/persist/secret.txt"
	if not os.path.exists(secret):
		with open(secret, "w") as f:
			f.write(str(uuid.uuid4()))
	return open(secret, "r").read()

app = Flask(__name__)
app.secret_key = GetOrCreateSecret()
app.config['MAX_CONTENT_LENGTH'] = 4000000000 # 4GB

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = '/'


class Base(DeclarativeBase):
  pass
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cardwars.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

badcharaters = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ";", "%", "^", "&", "(", ")", "{", "}", "[", "]"]

@app.route("/persist/version.txt")
def PersistVersion():
	with open("data/persist/version.txt", "r") as f:
		return f.read()

@app.route("/persist/updater_version.txt")
def PersistUpdaterVersion():
	with open("data/persist/updater_version.txt", "r") as f:
		return f.read()

class Admin(UserMixin, db.Model):
	username: Mapped[str] = mapped_column(db.String(80), primary_key=True, unique=True, nullable=False)
	password: Mapped[str] = mapped_column(db.String(80), nullable=False)
 
	def get_id(self):
		return str(self.username)
 
@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(user_id)
 
@app.route("/admin", methods=['GET', 'POST'])
def AdminPage():
	if request.method == 'GET':
		if current_user.is_authenticated:
			return render_template('admin.html', matches=Matches, version=PersistVersion(), updater_version=PersistUpdaterVersion(), tournament=GetTorunamentData())
		else:
			return render_template('login.html')
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db_user = Admin.query.filter_by(username=username).first()
		if db_user is None:
			return make_response("Invalid Username!", 400)
		if not bcrypt.check_password_hash(db_user.password, password):
			return make_response("Invalid Password!", 400)
		login_user(db_user)
		return redirect("/admin")

@app.route("/admin/logout")
def AdminLogout():
	logout_user()
	return redirect("/")

@login_required
@app.route("/admin/backup")
def AdminBackup():
    #get date and time
	now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
	print(now)
	os.makedirs("backup/" + now, exist_ok=True)
 
	#copy database
	shutil.copy("instance/cardwars.db", f"backup/{now}/cardwars.db")
 
	#copy persist folder
	shutil.copytree("data/persist", f"backup/{now}/persist")
 
	#zip
	shutil.make_archive("backup/" + now, 'zip', "backup/" + now)
 
	#delete folder
	shutil.rmtree("backup/" + now)
	
	Log("admin", "Backed up")
	
	return make_response("OK", 200)

class Player(db.Model):
	username = db.Column(db.String(80), primary_key=True, unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	game = db.Column(db.String(8192), nullable=True)
	icon = db.Column(db.String(128), nullable=False)
	deck = db.Column(db.String(1024), nullable=True)
	deck_rank = db.Column(db.String(16), nullable=False)
	landscapes = db.Column(db.String(1024), nullable=False)
	leader = db.Column(db.String(128), nullable=False)
	leader_level = db.Column(db.String(16), nullable=False)
	level = db.Column(db.String(16), nullable=False)
	trophies = db.Column(db.String(16), nullable=False)
	streak = db.Column(db.String(16), nullable=False)
	wins = db.Column(db.String(16), nullable=False)
	losses = db.Column(db.String(16), nullable=False)
	tournament_trophies = db.Column(db.String(16), nullable=False, default="0")
	tournament_wins = db.Column(db.String(16), nullable=False, default="0")
	tournament_losses = db.Column(db.String(16), nullable=False, default="0")
	tournament_outcome = db.Column(db.String(1024), nullable=False, default="[]")
 
	def as_dict(self):
		return {c.name: getattr(self, c.name) for c in self.__table__.columns}

@app.route("/")
def Index():
    return "200 App server running"

@app.route("/account/preAuth/")
def AccountPreAuth():
	data ={}
	return jsonify(data)

@app.route("/account/exists")
def AccountExists():
	username = request.args.get("user")

	if InvalidUsername(username):
		return "false"

	db_user = Player.query.filter_by(username=username).first()
 
	if db_user:
		return "true"

	return "false"

def EncryptPassword(password):
	return bcrypt.generate_password_hash(password).decode('utf-8')

def DecryptPassword(hashed, password):
	return bcrypt.check_password_hash(hashed, password)

@app.route("/account/create")
def AccountCreate():
	username = request.args.get("user")
	password = request.args.get("pass")
	
	if InvalidUsername(username):
		msg = "Invalid Username!"
		data = {
			"success": False,
			"message": msg
		}
		return jsonify(data)

	#check if username already exists
	db_user = Player.query.filter_by(username=username).first()
 
	if db_user:
		msg = "Account already exists!"
		data = {
			"success": False,
			"message": msg
		}
		return jsonify(data)


	#create account
	new_user = Player(
		username = username,
		password = EncryptPassword(password),
		game = None,
		icon = "CharacterIconAtlas",
		deck = None,
		deck_rank = "10",
		landscapes = "{\"landscape\":[\"Corn\",\"Corn\",\"Corn\",\"Swamp\"],}",
		leader = "Leader_Jake",
		leader_level = "1",
		level = "1",
		trophies = "0",
		streak = "0",
		wins = "0",
		losses = "0",
		tournament_trophies = "0",
		tournament_wins = "0",
		tournament_losses = "0",
		tournament_outcome = "[]"
	)
 
	db.session.add(new_user)
	db.session.commit()
 
	data = {
		"success": True,
		"message": "Success!"
	}
 
	Log("player", "Created account: " + username)
 
	return jsonify(data)


@app.route("/account/auth")
def AccountAuth():
	
	#check if username and password have any bad characters
	username = request.args.get("user")
	password = request.args.get("pass")

	#check if username is valid
	if InvalidUsername(username):
		msg = "Invalid Username!"
		data = {
			"success": False,
			"message": msg
		}
		return jsonify(data)

	#check if account exists
	db_user = Player.query.filter_by(username=username).first()
 
	if not db_user:
		msg = "Account does not exist!"
		data = {
			"success": False,
			"message": msg
		}
		return jsonify(data)
	
	#check if password is correct
	if not DecryptPassword(db_user.password, password):
		msg = "Incorrect Password!"
		data = {
			"success": False,
			"message": msg
		}
		return jsonify(data)
	else:
		msg = "Success!"
		data = {
			"success": True,
			"message": msg
		}
		return jsonify(data)

def InvalidUsername(username):
	username = username.lower()
	for char in badcharaters:
		if char in username:
			return True
	if username == 'ua' or username == 'guest':
		return True
	return False

@app.route("/persist/<username>/game", methods=['GET', 'PUT'])
def PersistGame(username):
	if InvalidUsername(username):
		return make_response("Invalid Username!", 400)
	
	if request.method == 'GET':
		db_user = Player.query.filter_by(username=username).first()
		if db_user.game is None:
			return make_response("No game found!", 404)
		return db_user.game

	if request.method == 'PUT':
		data = request.data
		db_user = Player.query.filter_by(username=username).first()
		db_user.game = data
		db.session.commit()
		return make_response("OK", 200)

@app.route("/persist/messages_received_ids")
def PersistMessagesReceivedIDs():
	return send_from_directory(directory="", path="data/persist/messages_received_ids.json", as_attachment=True, download_name="messages_received_ids.json")
	
@app.route("/persist/messages_get/<string:message>")
def PersistMessagesGet(message):
    #check if message exists
	if not os.path.exists(f"data/persist/messages/{message}.json"):
		return make_response("Message not found!", 404)
	return send_from_directory(directory="", path=f"data/persist/messages/{message}.json", as_attachment=True, download_name=f"{message}.json")

@app.route("/multiplayer/player/<string:username>")
def MultiplayerPlayer(username):
	db_user = Player.query.filter_by(username=username).first()

	mpdata = {
		"name": db_user.username,
		"icon": db_user.icon,
		"leader": db_user.leader,
		"level": db_user.level,
		"trophies": db_user.tournament_trophies
	}
	return jsonify(mpdata)

Matches = deque()

@app.route("/multiplayer/update_deck/", methods=['POST'])
def MultiplayerUpdateDeck():
	data = parse_qs(request.get_data().decode('utf-8'))
	data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
 
	if InvalidUsername(data["name"]):
		return make_response("Invalid Username!", 400)
  
	db_user = Player.query.filter_by(username=data["name"]).first()
	db_user.deck = data["deck"]
	db_user.deck_rank = data["deck_rank"]
	db_user.landscapes = data["landscapes"]
	db_user.leader = data["leader"]
	db_user.leader_level = data["leader_level"]
	db.session.commit()

	return make_response("OK", 200)

@app.route("/multiplayer/update_player/", methods=['POST'])
def MultiplayerUpdatePlayer():
	data = parse_qs(request.get_data().decode('utf-8'))
	data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
 
	if InvalidUsername(data["name"]):
		return make_response("Invalid Username!", 400)

	db_user = Player.query.filter_by(username=data["name"]).first()
	db_user.icon = data["icon"]
	db_user.level = data["level"]
	db.session.commit()

	return make_response("OK", 200)

class MatchData(db.Model):
	match_id = db.Column(db.String(255), primary_key=True)
	name = db.Column(db.String(255))
	icon = db.Column(db.String(255))
	deck = db.Column(db.String(255))
	landscapes = db.Column(db.String(255))
	leader = db.Column(db.String(255))
	leader_level = db.Column(db.String(255))
	wager_win = db.Column(db.String(255))
	wager_lose = db.Column(db.String(255))
	streak = db.Column(db.String(255))
	streak_bonus = db.Column(db.String(255))
	deck_rank = db.Column(db.String(255))
	expiration_date = db.Column(db.String(255))

	def as_dict(self):
		return {c.name: getattr(self, c.name) for c in self.__table__.columns}

@app.route("/multiplayer/matchmake/find/", methods=['POST'])
def MultiplayerMatchmakeFind():
	if request.method == 'POST':
		data = parse_qs(request.get_data().decode('utf-8'))
		data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
  
		if InvalidUsername(data["name"]):
			return make_response("Invalid Username!", 400)

		PlayerLevel = int(data["level"])
  
		Candidates = []
  

		db_users = Player.query.all()
		for otherdata in db_users:
			if otherdata.username != data["name"]:
				#Check if player is within a certain level range
				if abs(int(otherdata.level) - int(PlayerLevel)) <= 30:
					#Check if player has a valid deck
					if otherdata.deck != "" and otherdata.deck != None:
						Candidates.append(otherdata)

		if len(Candidates) > 0:
			#we found a match
			#choose a random player
			Opponent = random.choice(Candidates)
			return CreateMatch(data["name"], Opponent)
		Log("matchmaking", f"Couldn't find a match for {data['name']}, Level: {PlayerLevel}!")
		#we couldnt find a match
		return make_response("Couldn't find a match!", 404)
		
def CreateMatch(Player1, Player2):
	#get timestamp
	#example:2023-11-30T15:30:00
	
	expdate = (datetime.now()+timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
 
	#get player streak
	player1data = Player.query.filter_by(username=Player1).first()
 
	match_id = f"{Player1}-{Player2.username}-{uuid.uuid4()}"
 
	match = MatchData(
		match_id=match_id,
		name=Player2.username,
		icon=Player2.icon,
		deck=Player2.deck,
		landscapes=Player2.landscapes,
		leader=Player2.leader,
		leader_level=Player2.leader_level,
		wager_win=f"{random.randint(4, 10)}",
		wager_lose="1",
		streak=str(int(player1data.streak)),
		streak_bonus=str(min(int(player1data.streak), 4)),
		deck_rank=Player2.deck_rank,
		expiration_date=expdate
	)
 
	db.session.add(match)
	db.session.commit()
 
	print(f"Match Created: {match_id}") 
	
	return jsonify(match.as_dict())
  
@app.route("/multiplayer/matchmake/start/", methods=['POST'])
def MultiplayerMatchmakeStart():
	if request.method == 'POST':
		data = parse_qs(request.get_data().decode('utf-8'))
		data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}

		# find match
		match = MatchData.query.filter_by(match_id=data["match_id"]).first()

		if match:
			return match.deck
		else:
			#we couldnt find a match
			Log("matchmaking", f"Couldn't start a match for {data['name']}!")
			return make_response("Couldnt find a match!", 404)

@app.route("/multiplayer/matchmake/complete/", methods=['POST'])
def MultiplayerMatchmakeComplete():
	if request.method == 'POST':
		data = parse_qs(request.get_data().decode('utf-8'))
		data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
  
		match = MatchData.query.filter_by(match_id=data["match_id"]).first()
		if match:
			#add trophies
			db_user = Player.query.filter_by(username=data["name"]).first()
			if data["loss"] == "True":
				#Player lost
				#add to wager lose to player trophies
				db_user.trophies = str(int(db_user.trophies) + int(match.wager_lose))
				#add to tournament trophies
				db_user.tournament_trophies = str(int(db_user.tournament_trophies) + int(match.wager_lose))
				#reset streak
				db_user.streak = "0"
	
				db_user.losses = str(int(db_user.losses) + 1)
				db_user.tournament_losses = str(int(db_user.tournament_losses) + 1)
			else:
				#Player won
				#add to wager win to player trophies
				db_user.trophies = str(int(db_user.trophies) + int(match.wager_win))
				#add to tournament trophies
				db_user.tournament_trophies = str(int(db_user.tournament_trophies) + int(match.wager_win))
				#increase streak
				db_user.streak = str(int(db_user.streak) + 1)
	
				db_user.wins = str(int(db_user.wins) + 1)
				db_user.tournament_wins = str(int(db_user.tournament_wins) + 1)
			db.session.commit()
	
			#remove match
			db.session.delete(match)
			db.session.commit()

			print(f"Match Completed: {data['match_id']}")

			response = {
				"data":{
					"trophies": str(db_user.tournament_trophies),
				}
			}
			return jsonify(response)
		else:
			#we couldn't find a match
			Log("matchmaking", f"Couldn't complete a match for {data['name']}!")
			return make_response("Couldn't complete a match!", 404)

def GetTorunamentData():
	with open("data/persist/tournament/active.json", "r") as f:
		data = json.load(f)
	return data

#Send prizes
@app.route("/multiplayer/tournament/player/", methods=['GET'])
def MultiplayerTournamentPlayer():
	#get username from url
	username = request.args.get('username')
 
	db_user = Player.query.filter_by(username=username).first()
 
	if db_user is None:
		return make_response("No player found!", 404)

	data = {
		"success": True,
		"data": json.loads(db_user.tournament_outcome)
	}

	return jsonify(data)

#Player claims prizes
@app.route("/multiplayer/tournament/complete/", methods=['POST'])
def MultiplayerTournamentComplete():
	#get username from post
	data = parse_qs(request.get_data().decode('utf-8'))
	data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
 
	db_user = Player.query.filter_by(username=data["username"]).first()
 
	if db_user is None:
		return make_response("No player found!", 404)

	#Clear player tournament data
	db_user.tournament_outcome = "[]"
	db.session.commit()
	return make_response("OK", 200)

@app.route("/multiplayer/tournament/expiration/", methods=['GET'])
def MultiplayerTournamentExpiration():
	
	tournament = GetTorunamentData()
	
	data = {
		"success": True,
		"data": {
			"tournament_id": str(tournament["tournament_id"]),
			"time": str(tournament["end_date"]),
		}
	}

	return jsonify(data)



#Global Leaderboard
@app.route("/multiplayer/active_leaderboard/", methods=['GET'])
def MultiplayerActiveLeaderboard():
    
    #get all players with more than 1 win
	db_users = Player.query.all()
	userdata = []
 
	for user in db_users:
		if int(user.trophies) > 0:
			userdata.append({
				"rank": 0,
				"prev_rank": 0,
				"player_name": user.username,
				"icon": user.icon,
				"leader": user.leader,
				"leader_level": user.leader_level,
				"trophies": user.trophies,
				"wins": user.wins,
				"losses": user.losses
			})
   
	#sort by trophies
	userdata.sort(key=lambda x: int(x["trophies"]), reverse=True)
 
	#set rank
	for i in range(len(userdata)):
		userdata[i]["rank"] = str(i + 1)
		userdata[i]["prev_rank"] = str(i + 1) #Temporary
    
	data = {
		"success": True,
		"data": userdata
	}
	return jsonify(data)

#Tournament rank
@app.route("/multiplayer/active_leaderboard/rank/", methods=['GET'])
def MultiplayerActiveLeaderboardRank():
		
	db_users = Player.query.all()
	userdata = []
 
	for user in db_users:
		if int(user.tournament_trophies) > 0:
			userdata.append({
				"rank": 0,
				"player_name": user.username,
				"trophies": user.tournament_trophies,
			})
   
	#sort by trophies
	userdata.sort(key=lambda x: int(x["trophies"]), reverse=True)
 
	#set rank
	for i in range(len(userdata)):
		userdata[i]["rank"] = str(i + 1)
  
	#find user in userdata
	username = request.args.get('username')
		
	for i in range(len(userdata)):
		if userdata[i]["player_name"] == username:
			data = {
				"success": True,
				"data": {
					"rank": i + 1
				}
			}
			return jsonify(data)
    
	return make_response("User not found!", 404)

#Global rank
@app.route("/multiplayer/active_leaderboard/globalrank/", methods=['GET'])
def MultiplayerActiveLeaderboardGlobalRank():
		
	db_users = Player.query.all()
	userdata = []
 
	for user in db_users:
		if int(user.trophies) > 0:
			userdata.append({
				"rank": 0,
				"player_name": user.username,
				"trophies": user.trophies,
			})
   
	#sort by trophies
	userdata.sort(key=lambda x: int(x["trophies"]), reverse=True)
 
	#set rank
	for i in range(len(userdata)):
		userdata[i]["rank"] = str(i + 1)
  
	#find user in userdata
	username = request.args.get('username')
		
	for i in range(len(userdata)):
		if userdata[i]["player_name"] == username:
			data = {
				"success": True,
				"data": {
					"rank": i + 1
				}
			}
			return jsonify(data)
    
	return make_response("User not found!", 404)

#Tournament Leaderboard
@app.route("/multiplayer/active_leaderboard/<string:username>", methods=['GET'])
def MultiplayerActiveLeaderboardUser(username):
	#get all players with more than 0 trophies
	db_users = Player.query.all()
	userdata = []
 
	for user in db_users:
		if int(user.tournament_trophies) > 0:
			userdata.append({
				"rank": 0,
				"prev_rank": 0,
				"player_name": user.username,
				"icon": user.icon,
				"leader": user.leader,
				"leader_level": user.leader_level,
				"trophies": user.tournament_trophies,
				"wins": user.tournament_wins,
				"losses": user.tournament_losses
			})
   
	#sort by trophies
	userdata.sort(key=lambda x: int(x["trophies"]), reverse=True)
 
	#set rank
	for i in range(len(userdata)):
		userdata[i]["rank"] = str(i + 1)
		userdata[i]["prev_rank"] = str(i + 1) #Temporary
  
	#only get top 100
	userdata = userdata[:100]
    
	data = {
		"success": True,
		"data": userdata
	}
	return jsonify(data)

def scheduled_task():
    while True:
        Update()
        time.sleep(1)

def Update():
	with app.app_context():
		#Get tournament data
		tournament = GetTorunamentData()

		#Check if end date has passed
		enddate = datetime.strptime(tournament["end_date"], "%Y-%m-%dT%H:%M:%S").timestamp()
		if time.time() > enddate:
				TournamentEnd()
    
def TournamentEnd():
	
	#Get tournament data
	tournament = GetTorunamentData()
 
 
	#get all players
	db_users = Player.query.all()
	userdata = []

	#rank players
	for user in db_users:
		if int(user.tournament_trophies) > 0:
			userdata.append({
				"rank": 0,
				"player_name": user.username,
				"tournament_trophies": user.tournament_trophies
			})
   
	#sort by trophies
	userdata.sort(key=lambda x: int(x["tournament_trophies"]), reverse=True)
 
	#set rank
	for i in range(len(userdata)):
		userdata[i]["rank"] = str(i + 1)
  
	#Only keep top 100
	userdata = userdata[:100]
 
	#log players
	for i in range(len(userdata)):
		Log("tournament", f"Player {userdata[i]['player_name']} finished tournament {tournament['tournament_id']} with rank {userdata[i]['rank']}")
 
	#go through each player and add their outcome
	for i in range(len(userdata)):
		user = Player.query.filter_by(username=userdata[i]["player_name"]).first()
		useroutcome = {
			"tournament_id": str(tournament["tournament_id"]),
			"outcome": str(userdata[i]["rank"]),
		}
		playeroutcome = json.loads(user.tournament_outcome)
		playeroutcome.append(useroutcome)
		#append outcome to tournament_outcome
		user.tournament_outcome = json.dumps(playeroutcome)

		#reset tournament trophies, wins, losses
		user.tournament_trophies = "0"
		user.tournament_wins = "0"
		user.tournament_losses = "0"

  
		db.session.commit()
  
	Log("tournament", f"Tournament {tournament['tournament_id']} ended")
  
	#Next tournament
	tournament["tournament_id"] = int(tournament["tournament_id"]) + 1
	#add 14 days to end
	end_date = datetime.strptime(tournament["end_date"], "%Y-%m-%dT%H:%M:%S").timestamp()
	tournament["end_date"] = datetime.fromtimestamp(end_date + 60 * 60 * 24 * 14).strftime("%Y-%m-%dT%H:%M:%S")
 
	#save
	with open("data/persist/tournament/active.json", "w") as f:
		json.dump(tournament, f)
  
def Log(category, message):
	os.makedirs("data/persist/logs", exist_ok=True)
	date = datetime.now().strftime("%Y-%m-%d")
	time = datetime.now().strftime("%H:%M:%S")
	with open("data/persist/logs/" + date + ".txt", "a") as f:
		log = f"{time} - [{category.upper()}] - {message} \n"
		f.write(log)
		print(log)

#Create default admin if it doesn't exist and returns the password
#If it does exist, returns None
def CreateDefaultAdmin() -> str:
	db_user = Admin.query.filter_by(username="admin").first()
	if db_user is None:
		password = uuid.uuid4().hex
		db_user = Admin(username="admin", password=EncryptPassword(password))
		db.session.add(db_user)
		db.session.commit()
		return password
	return None

def AppSetup():
	with app.app_context():

		#create some needed folders
		os.makedirs("data/persist/tournament", exist_ok=True)
		os.makedirs("data/persist/logs", exist_ok=True)
		os.makedirs("data/persist/messages", exist_ok=True)

		#create default game files
		if not os.path.exists("data/persist/version.txt"):
			with open("data/persist/version.txt", "w") as f:
				f.write("1.0.0")

		if not os.path.exists("data/persist/updater_version.txt"):
			with open("data/persist/updater_version.txt", "w") as f:
				f.write("1.0.0")

		if not os.path.exists("data/persist/tournament/active.json"):
			with open("data/persist/tournament/active.json", "w") as f:
				#get current date and add 14 days
				end_date = datetime.now() + timedelta(days=14)
				json.dump({"tournament_id": 0, "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S")}, f)


		#Create database
		db.create_all()
		update_thread = threading.Thread(target=scheduled_task)
		update_thread.start()

		#Create and show admin login if it doesn't exist
		admin_password = CreateDefaultAdmin()
		if admin_password is not None:
			print(f"Created 'admin' user with password: {admin_password}")

if __name__ == '__main__':
	AppSetup()
	app.run(debug=args.debug, port=args.port)
else:
	Log("server", "Starting server...")
	AppSetup()
 