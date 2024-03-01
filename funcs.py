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
from dotenv import load_dotenv

load_dotenv()
def generate_password(length: int) -> str:
  """
  Returns a random password THAT ISNT ENCRYPTED.
  """
  return ''.join(random.choice(string.printable) for i in range(length)) # just some random characters. not encrypted. I have no idea what this is used for


def parse_token(token: str) -> list:
  """
  Parses a token into username and password. If the token is very 'invalid' (aka doesn't have a | character) it returns ["N","A"]
  """
  result: list = []

  result = token.split("|")
  if(result.__len__()!=2):
    result = ["N","A"] # returns 'N,A' if the token is garbled.
  return result

def user_logged_in(user):
  """
  Updates the 'last-login' to current date.
  """
  data = load_data()
  data[user]["last-login"] = time.time()
  save_data(data) # optimized! raah. 1.3.2024@20:18:16
  

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
  The result should be ignored, as it always returnes True
  """
  file = open('userinfo.json','w') # open the file etc etc
  lock_file(file) # just in case"
  json.dump(data,file)
  unlock_file(file) # unlock, we don't want a locking thingymajig!
  file.close()
  return True # it always returns true, even if the write fails
  
def create_user(username: str, password: str, email: str, language: str, country: str, time_signed_up) -> bool:
  """
  Creates an user.
  """
  data = load_data()  
  token = str(sha256(username.encode("utf-8")).hexdigest()) # the token is just the username hashed
                                                            # seems like a bad ideea, but dont worry! we'll
                                                            # change it at some point. and ohh actually, it isnt'
                                                            # even the token, its just 'username'. Stupid naming, ik
  password: str = str(sha256(password.encode("utf-8")).hexdigest()) # password -> sha256 password 
  if token in data: # If the username already exists, dont let the user sign up
    return False
  else:
    data[token] = {}
    if language==None:
      language = "en-US" # If language isnt specified, set it to english
    fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # The hashing engine
    data[token]['email'] = (fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8'))
    data[token]['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8')
    data[token]["display-name"] = (fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8'))
    data[token]['lang'] = language # their locale gotten from js!
    data[token]['country'] = country
    data[token]["created"] = time_signed_up
    data[token]["last-login"] = time.time() # :sunglasses:
    data[token]["permissions"] = {} # the permissions
    data[token]["domains"] = {} # the domains they have
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

def load_user(token: str) -> bool: # 'load_user' is such a terrible name
  """ 
  Checks if token is valid.
  """
  # doesn't load_token do this excact same thing???
  
  if load_token(token):
    user_logged_in(parse_token(token)[1]) # make the user's "last logged in" to the current date
    return True # what? ig the token is valid?
  return False # what? ig the token is invalid?
  
def get_user_data(token: str): # kys if you abuse this! <3 I wrote the whole account system in a day, don't blame me for the horrible security
  """
  Returns the user's data.
  """
  # I don't think this is ever used anywhere, I'm leaving it just in case !
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if data.get(username,None) != None:
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")):
      fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
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
  valid = all(c in allowed for c in domain) # this *might* work, super hacky tho
  return valid

def check_domain(domain: str) -> tuple: # if the domain is actually domainable! cloudflare will cry otherwise.
  headers = {
    "X-Auth-Email": os.getenv("EMAIL"), 
    "Authorization": "Bearer "+os.getenv('CF_KEY_R') # cloudflare read token
  }
  if(is_domain_valid(domain)==False):
    return "Bad Request",400 # buddy, it aint a valid domain
  response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records?name={domain+'.frii.site'}", headers=headers) # hey cloudflare my beloved, is this available?
  if(response.json().get("result_info").get("total_count")==0): # if its ok and if the total count of records named that are 0.
    return "OK",200 # everything is fine! just register it already bruv
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
   
def give_domain(domain: str, ip: str, token: str) -> tuple: # returns html status code: ex: 'OK', 200
  data = load_data() # load the 'database' (lmao)
  username = parse_token(token)[1] # get the username from the token
  password = parse_token(token)[0] # again... why isn't this a function? 'get_username_and_password_from_token', ohh, were doing that already. mb
  print(check_domain(domain))
  amount_of_domains: int = data[username]["domains"].__len__() # the amount of domains the user has.
  if(data[username]["permissions"].get("max_domains",1)<=amount_of_domains): # if user's max domains are more than the current amount of domains
    if(check_domain(domain)[1]==200): # If is a valid domain.
      if (data.get(username,None) != None): # if user exists, check so we are not 'fucked'
        if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
          headers = {
            "Content-Type":"application/json", # tryna not to confuse cf :(
            "Authorization": "Bearer "+os.getenv('CF_KEY_W'), # cloudflare token to write.
            "X-Auth-Email": os.getenv("EMAIL") # tbh: I have no idea if this is required.
          }
          fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # init fernet n shi
          data_ = {
            "content": ip,
            "name": domain+'.frii.site', # because 'domain' is *only* the subdomain (example.frii.site->example)
            "proxied": False, # so cloudflare doesn't proxy the content
            "type": "A", # for ipv4
            "comment": "Issued by "+(fernet.decrypt(str.encode(data[username]["display-name"]))).decode("utf-8"), # just a handy-dandy lil feature that shows the admin (me) who registered the domain
            "ttl": 1 # auto ttl
          }
          response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records",headers=headers,json=data_)
          if(response.status_code==200):
            add_domain_to_user(true_domain=True,user=username,domain=domain,ip=ip,domain_id=(response.json().get("result").get("id")))
          return "OK", 200
        else:
          return 'Unauthorized', 401 # pal does NOT have the correct creds
      else:
        return 'Not Found', 404 # user does not exist???? 
    else:
      return 'Conflict', 409 # it aint a valid domain mate
  else: 
    return 'Method Not Allowed', 405 # if the user is trying to make more domains than they are allowed to.

def modify_domain(domain: str, token: str, new_ip: str) -> tuple:
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if (data.get(username,None) != None): # if user exists
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
      if(data[username]["domains"].get(domain,False)!=False):
        fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
        data_ = {
          "content": new_ip,
          "name": domain+".frii.site",
          "proxied": False,
          "type": "A",
          "comment": "Changed by "+(fernet.decrypt(str.encode(data[username]['display-name']))).decode("utf-8") # a handy dandy lil message
        }
        headers = {
          "Content-Type": "application/json",
          "Authorization": "Bearer "+os.getenv('CF_KEY_W'),
          "X-Auth-Email": os.getenv("EMAIL")
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records/{data[username]['domains'][domain]['id']}",json=data_,headers=headers)
        if(response.status_code==200):
          add_domain_to_user(user=username,domain=domain,ip=new_ip,domain_id=None)
        return "OK",200 # if its ok, then its ok!
      else:
        return 'Forbidden', 403 # if user does not own the domain
    else: 
      return 'Unauthorized', 401 # wrong creds :(
  else:
    return 'Not Found', 404 # the user does not exist !!1!1!1 what the fuck
  
def get_user_domains(token: str) -> dict: 
  data = load_data()
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if (data.get(username,None) != None): # if user exists
    if bcrypt.checkpw(password.encode("utf-8"), data[username]["password"].encode("utf-8")): # correct creds
      if(data[username].get("domains",[]).__len__()!=0): # if they own a domain
          return data[username]["domains"] # return the domains that the user owns.
      else:
        return {"Status": 404, "Description": "User has no domains"} # Ig im using dicts now,,,
    else:
      return {"Status": 401, "Description":"Invalid login."}
  else:
    return {"Status": 404, "Description": "User does not exist?"} # The user *somehow* doesn't exist??
  
# thats it, finally!