"""
For the love of god, please switch away from json to something like MySQL. Json is so slow :(
"""
import json
from hashlib import sha256
from cryptography.fernet import Fernet
import os
from lock import lock_file, unlock_file
import bcrypt
import string
import random
import time
import requests
import string

def generate_password(length: int) -> str:
  """
  Returns a random password THAT ISNT ENCRYPTED.
  """
  return ''.join(random.choice(string.printable) for i in range(length))


def parse_token(token: str) -> list:
  """
  Parses a token into username and password. If the token is very 'invalid' (aka doesn't have a | character) it returns ["N","A"]
  """
  result: list = []

  result = token.split("|")
  if(result.__len__()!=2):
    result = ["N","A"]
  return result

def user_logged_in(user):
  """
  Updates the 'last-login' to current date.
  """
  data = load_data()
  data[user]["last-login"] = time.time()
  file = open("userinfo.json", "w")
  lock_file(file)
  json.dump(data,file)
  unlock_file(file)
  file.close()

def load_data() -> dict:
  """
  Get data from userinfo.json
  """
  with open('userinfo.json','r') as f:
    data = json.load(f)
  return data

def save_data(data: dict) -> bool:
  """
  Saves data to file. 
  It does not append, it simply takes the data and overwrites the file.
  """
  file = open('userinfo.json','w')
  lock_file(file)
  json.dump(data,file)
  unlock_file(file)
  file.close()
  return True
  
def create_user(username: str, password: str, email: str, language: str, country: str, time_signed_up: float | int) -> bool:
  """
  Creates an user.
  """
  data = load_data()  
  token = str(sha256(username.encode("utf-8")).hexdigest())
  password: str = str(sha256(password.encode("utf-8")).hexdigest())
  if token in data: # If the username already exists, dont let the user sign up
    return False
  else:
    data[token] = {}
    if language==None:
      language = "en-US" # If language isnt specified, set it to english
    fernet = Fernet(bytes(os.environ['ENC_KEY'], 'utf-8')) # The hashing engine
    data[token]['email'] = (fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8'))
    data[token]['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8')
    data[token]["display-name"] = (fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8'))
    data[token]['lang'] = language
    data[token]['country'] = country
    data[token]["created"] = time_signed_up
    data[token]["last-login"] = time.time()
    data[token]["domains"] = {}
    save_data(data) # Saves that data
    return True

def load_token(token):
  """
  Checks if username + passwords are correcct
  """
  data = load_data() # Loads the data
  username = parse_token(token)[1] # Gets the second part of token (username)
  password = parse_token(token)[0] # Gets the first part of token (password)
  if(data.__contains__(username)):
    return bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")) # Checks if passwords match
  else:
    return False

def load_user(token: str) -> bool:
  """
  Checks if token is valid.
  """
  if load_token(token):
    user_logged_in(parse_token(token)[1])
    return True
  return False
  
def get_user_data(token: str) -> dict | bool | int: # kys if you abuse this! <3 I wrote the whole account system in a day, don't blame me for the horrible security
  """
  Returns the user's data.
  """
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if data.get(username,None) != None:
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")):
      fernet = Fernet(bytes(os.environ['ENC_KEY'], 'utf-8'))
      return {
              "username": (fernet.decrypt(str.encode(data[username]["display-name"]))).decode("utf-8"),
              "email": (fernet.decrypt(str.encode(data[username]["email"]))).decode("utf-8"),
              "lang": data[username]["lang"],
              "country": data[username]["country"],
              "created": data[username]["created"]
            }
    else:
      False
  else:
    return 404


def save_user(user: str) -> bool:
  """
  Doesnt do anything atm
  """
  data = load_data()
  return True

def is_domain_valid(domain: str) -> bool:
  allowed = list(string.ascii_letters)
  allowed.extend(list(string.digits))
  allowed.extend([".","-"])
  valid = all(c in allowed for c in domain)
  return valid

def check_domain(domain: str) -> tuple:
  headers = {
    "X-Auth-Email": os.environ["EMAIL"], 
    "Authorization": "Bearer "+os.environ['CF_KEY_R']
  }
  if(is_domain_valid(domain)==False):
    return "Bad Request",400
  response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{os.environ['ZONEID']}/dns_records?name={domain+'.frii.site'}", headers=headers)
  if(response.json().get("result_info").get("total_count")==0):
    return "OK",200
  return "Conflict",409 # I don't really know, just guessing lol

def add_domain_to_user(user: str, domain: str, ip: str, domain_id: str = None, true_domain: bool=None) -> bool:
  data = load_data()
  if(data[user].get("domains",{}).get(domain,None)== None): # Tried fixing an issue with the server forgetting the 'id', it somehow did not fix anything. Decided to leave it tho!
    data[user]["domains"][domain] = {}
  data[user]["domains"][domain]["ip"] = ip
  data[user]["domains"][domain]["registered"] = time.time() 
  if(true_domain!=None): # 'true_domain' = A record that points to an ip address, 'false_domain' is just a redirect.
    data[user]["domains"][domain]["true-domain"] = true_domain
  if(domain_id!=None): # If the id isn't none, then override it. Ignore otherwise.
    data[user]["domains"][domain]["id"] = domain_id
  return save_data(data)
  
def give_domain(domain: str, ip: str, token: str) -> tuple:
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  print(check_domain(domain))
  if(check_domain(domain)[1]==200): # If is a valid domain.
    if (data.get(username,None) != None): # if user exists, check so we are not 'fucked'
      if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
        headers = {
          "Content-Type":"application/json",
          "Authorization": "Bearer "+os.environ['CF_KEY_W'],
          "X-Auth-Email": os.environ["EMAIL"]
        }
        fernet = Fernet(bytes(os.environ['ENC_KEY'], 'utf-8'))
        data_ = {
          "content": ip,
          "name": domain+'.frii.site',
          "proxied": False,
          "type": "A",
          "comment": "Issued by "+(fernet.decrypt(str.encode(data[username]["display-name"]))).decode("utf-8"),
          "ttl": 1
        }
        response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{os.environ['ZONEID']}/dns_records",headers=headers,json=data_)
        if(response.status_code==200):
          add_domain_to_user(true_domain=True,user=username,domain=domain,ip=ip,domain_id=(response.json().get("result").get("id")))
        return "OK", 200
      else:
        return 'Unauthorized', 401
    else:
      return 'Not Found', 404 # user does not exist???? 
  else:
    return 'Conflict', 409

def modify_domain(domain: str, token: str, new_ip: str) -> tuple:
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if (data.get(username,None) != None): # if user exists
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
      if(data[username]["domains"].get(domain,False)!=False):
        fernet = Fernet(bytes(os.environ['ENC_KEY'], 'utf-8'))
        data_ = {
          "content": new_ip,
          "name": domain+".frii.site",
          "proxied": False,
          "type": "A",
          "comment": "Changed by "+(fernet.decrypt(str.encode(data[username]['display-name']))).decode("utf-8")
        }
        headers = {
          "Content-Type": "application/json",
          "Authorization": "Bearer "+os.environ['CF_KEY_W'],
          "X-Auth-Email": os.environ["EMAIL"]
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{os.environ['ZONEID']}/dns_records/{data[username]['domains'][domain]['id']}",json=data_,headers=headers)
        if(response.status_code==200):
          add_domain_to_user(user=username,domain=domain,ip=new_ip,domain_id=None)
        return "OK",200
      else:
        return 'Forbidden', 403
    else:
      return 'Unauthorized', 401
  else:
    return 'Not Found', 404 
  
def get_user_domains(token: str) -> dict: 
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if (data.get(username,None) != None): # if user exists
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
      if(data[username].get("domains",[]).__len__()!=0):
          return data[username]["domains"]
      else:
        return {"Status": 404, "Description": "User has no domains"}
    else:
      return {"Status": 401, "Description":"Invalid login."}
  else:
    return {"Status": 404, "Description": "User does not exist?"} # The user *somehow* doesn't exist??