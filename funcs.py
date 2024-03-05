"""
For the love of god, please switch away from json to something like MySQL. Json is so slow :(
"""
import json
from hashlib import sha256
from cryptography.fernet import Fernet
import os
import bcrypt
import string
import random
import time
import requests
from dotenv import load_dotenv
import resend
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.cursor import Cursor
verif_codes: dict = {}

load_dotenv()
resend.api_key = os.getenv("RESEND_KEY")
cluster: MongoClient = MongoClient(os.getenv("MONGODB_URL"))
db: Database = cluster["database"]
collection: Collection = db["frii.site"]

def generate_password(length: int) -> str:
  """
  Returns a random password THAT ISNT ENCRYPTED.
  """
  return ''.join(random.choice(string.printable) for i in range(length)) # just some random characters. not encrypted. I have no idea what this is used for

def password_is_correct(username: str, password: str) -> bool:
  data = get_data(username=username)
  return bcrypt.checkpw(password.encode("utf-8"), data["password"].encode("utf-8")) # correct creds

def generate_random_pin(lenght: int) -> int:
  return int(''.join(random.choice(string.digits) for i in range(lenght)))

def parse_token(token: str) -> list:
  """
  Parses a token into password and username. If the token is very 'invalid' (aka doesn't have a | character) it returns ["N","A"], if the token is empty, it retusn ["X,"X"]
  [password, username] # dumb ik
  """
  result: list = []
  try:
    result = token.split("|")
  except AttributeError:
    result = ["X","X"]
  if(result.__len__()!=2):
    result = ["N","A"] # returns 'N,A' if the token is garbled.
  return result

def user_logged_in(user):
  """
  Updates the 'last-login' to current date.
  """
  update_data(username=user,key="last-login",value=time.time())
  

def save_data(data: dict) -> bool:
  """
  Saves data to mongodb
  """
  collection.insert_one(data)
  return True # it always returns true, even if the write fails
  
def update_data(username: str, key: str, value: any) -> None:
  collection.update_one(
    {"_id": username},
    {"$set":{key:value},},
    upsert=False
  )

def get_data(username: str, only_first_one=True) -> dict:
  cursor: Cursor
  results_found: list = []
  cursor = collection.find({"_id":username})
  for result in cursor:
    results_found.append(result)
  if(results_found.__len__()!=0):
    if(only_first_one):
      return results_found[0]
    return result
  else:
    raise IndexError("No matches for username.")
  
def user_exists(token: str=None, username: str=None) -> bool:
  """_summary_

  Args:
      token (str, optional): Token of the user
      username (str, optional): Encrypted username of user. ([1] of token)

  Raises:
      ValueError: if token nor username is specified

  Returns:
      bool: if the user exists
  """
  print(token)
  cursor: Cursor
  results_found: list = []
  if(token == None and username == None):
    raise ValueError("Neither token or username was specified.")
  if(token != None):
    username = parse_token(token)[1]
    if username=="X":
      return False
  cursor = collection.find({"_id":username})
  for result in cursor:
    results_found.append(result)
  return results_found.__len__()!=0
  
def create_user(username: str, password: str, email: str, language: str, country: str, time_signed_up) -> bool:
  """
  Creates an user.
  """
  
  username = str(sha256(username.encode("utf-8")).hexdigest()) # the token is just the username hashed
                                                            # seems like a bad ideea, but dont worry! we'll
                                                            # change it at some point. and ohh actually, it isnt'
                                                            # even the token, its just 'username'. Stupid naming, ik
  password: str = str(sha256(password.encode("utf-8")).hexdigest()) # password -> sha256 password 
  if user_exists(username=username): # If the username already exists, dont let the user sign up.
    return False
  else:
    data: dict = {}
    if language==None:
      language = "en-US" # If language isnt specified, set it to english
    fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # The hashing engine
    data["_id"] = username
    data['email'] = (fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8')) # the encrypted email, but it is less encrypted
    data['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8') # the encrypted password
    data["display-name"] = (fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8')) # their display name, I don't think this can be changed tho lol
    data['lang'] = language # their locale gotten from js!
    data['country'] = country # their country
    data["created"] = time_signed_up
    data["last-login"] = time.time() # :sunglasses:
    data["permissions"] = {} # the permissions
    data["verified"] = False # the user has not verified their email
    data["domains"] = {} # the domains they have
    save_data(data) # Saves that data
    return True

def load_token(token):
  """
  Checks if username + passwords are correcct
  """
  username = parse_token(token)[1] # Gets the second part of token (username)
  password = parse_token(token)[0] # Gets the first part of token (password)
  if(user_exists(token=token)): # if the account exists
    return password_is_correct(username=username,password=password) # Checks if passwords match
  else:
    return False

def load_user(token: str) -> bool: # 'load_user' is such a terrible name
  """ 
  Checks if token is valid.
  """
  # doesn't load_token do this excact same thing???
  if load_token(token=token):
    username: str = parse_token(token)[1]
    if(username=="X"):
      return False
    user_logged_in(username) # make the user's "last logged in" to the current date
    return True # what? ig the token is valid?
  return False # what? ig the token is invalid?
  
def get_user_data(token: str): # kys if you abuse this! <3 I wrote the whole account system in a day, don't blame me for the horrible security
  """
  Returns the user's data.
  """
  # I don't think this is ever used anywhere, I'm leaving it just in case !
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 405
  try:
    data = get_data(username=username)
  except IndexError: # user does not exist
    return 404
  if(user_exists(username=username)):
    if password_is_correct(username=username,password=password):
      fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
      return {
              "username": (fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"),
              "email": (fernet.decrypt(str.encode(data["email"]))).decode("utf-8"),
              "lang": data["lang"],
              "country": data["country"],
              "created": data["created"]
            }
    else:
      False
  else:
    return 404


def save_user(user: str) -> bool:
  """
  Doesnt do anything atm
  """
  raise NotImplementedError("This function does not do anything")

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

def add_domain_to_user(user: str, domain: str, ip: str,  type: str=None, domain_id: str = None, true_domain: bool=None) -> bool:
  try:
   data = get_data(username=user)
  except IndexError:
    return False
  if(data.get("domains",{}).get(domain,None)==None): # if the user is registering it for the first time, instead of updating it
    data["domains"][domain] = {}
  data["domains"][domain]["ip"] = ip
  data["domains"][domain]["registered"] = time.time() 
  if(type!=None):
    data["domains"][domain]["type"] = type # the record type; A, CNAME, or TXT
  if(true_domain!=None): # 'true_domain' = A record that points to an ip address, 'false_domain' is just a redirect.
    data["domains"][domain]["true-domain"] = true_domain
  if(domain_id!=None): # If the id isn't none, then override it. Ignore otherwise.
    data["domains"][domain]["id"] = domain_id
  return update_data(username=user,key="domains",value=data["domains"])
   
   
def give_domain(domain: str, ip: str, token: str, type: str) -> tuple: # returns html status code: ex: 'OK', 200
  username = parse_token(token)[1] # get the username from the token
  password = parse_token(token)[0] # again... why isn't this a function? 'get_username_and_password_from_token', ohh, were doing that already. mb
  if(username=="X"):
    return 'Precondition Failed', 412
  try:
    data = get_data(username=username) # load the 'database' (lmao)
  except IndexError:
    return 'Not Found', 404
  if(type not in ["A","CNAME","TXT"]):
    return 'Method Not Allowed', 405 # The type is invalid.
  amount_of_domains: int = data["domains"].__len__() # the amount of domains the user has.
  if(is_user_verified(token)[1]!=200):
    return 'Bad Request', 400 # user is not verified, therefore cannot register a domain.
  if(amount_of_domains <= data["permissions"].get("max_domains",3)): # if user's max domains are more than the current amount of domains
    if(check_domain(domain)[1]==200 or type=="TXT" or type=="CNAME"): # If is a valid domain.
      if(user_exists(token=token)): # if user exists, check so we are not 'fucked'
        if password_is_correct(username=username,password=password): # correct creds
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
            "type": type.strip(), # the type of the record.
            "comment": "Issued by "+(fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"), # just a handy-dandy lil feature that shows the admin (me) who registered the domain
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
    return f'Method Not Allowed', 405 # if the user is trying to make more domains than they are allowed to.

def modify_domain(domain: str, token: str, new_ip: str) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  if (user_exists(token=token)):
    data = get_data(username=username)
    if password_is_correct(username=username,password=password): # correct creds
      domains: dict = data["domains"]
      if(domain in domains): # if the doman exists
        fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8'))
        data_ = {
          "content": new_ip,
          "name": domain+".frii.site",
          "proxied": False,
          "type": domains.get(domain,{}).get("type","A"),
          "comment": "Changed by "+(fernet.decrypt(str.encode(data['display-name']))).decode("utf-8") # a handy dandy lil message
        }
        headers = {
          "Content-Type": "application/json",
          "Authorization": "Bearer "+os.getenv('CF_KEY_W'),
          "X-Auth-Email": os.getenv("EMAIL")
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('ZONEID')}/dns_records/{data['domains'][domain]['id']}",json=data_,headers=headers)
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
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  if (user_exists(token=token)): # if user exists
    data = get_data(username=username)
    
    if password_is_correct(username=username,password=password): # correct creds
      if(data.get("domains",[]).__len__()!=0): # if they own a domain
          return data["domains"] # return the domains that the user owns.
      else:
        return {"Status": 404, "Description": "User has no domains"} # Ig im using dicts now,,,
    else:
      return {"Status": 401, "Description":"Invalid login."}
  else:
    return {"Status": 404, "Description": "User does not exist?"} # The user *somehow* doesn't exist??

def send_verify_email(token: str) -> tuple:
  global verif_codes
  """
  Send a verification code to user.

  Args:
      email (str): the user's email
      username (str): the username.
  Returns:
      HTTP status code if the email got sent.
  """
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  data = get_data(username=username)
  fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # The hashing engine
  if(data["verified"]==False):
    if password_is_correct(username=username,password=password): # correct creds
      email = (fernet.decrypt(str.encode(data["email"]))).decode("utf-8") # decrypt the email
      verif_codes[email] = {}
      verif_codes[email]["code"] = generate_random_pin(7)
      verif_codes[email]["expires"] = round(time.time())+5*60 # the current time + 5 minutes
      
      r = resend.Emails.send({ # for some reason this email *always* goes to spam, so someone should warn the user lol
        "from": 'send@frii.site', # do not change this. 
        "to": email, # who the email should be sent to
        "subject": "Verification", # TODO better name
        "html": f"""
        <h1>Hello {username}</h1>,
        your verification code is <strong>{verif_codes.get(email,{}).get('code','Severe server error')}</strong>.
        <h6>This code will expire in 5 minutes.</h6>
        """
        # TODO make it more beautiful.
      })
      return 'OK',200 # the email got sent? idk what resend.Emails.send returns if it's unsuccesful, because it isnt documented (as of 2.3.2024 ddmmyyyy)
    else:
      return 'Unauthorized', 401 # wrong passowrd mate
  else:
    return 'Conflict',409 # user is already verified
  
def verify_email(token: str, code: int) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  data = get_data(username=username)
  fernet = Fernet(bytes(os.getenv('ENC_KEY'), 'utf-8')) # The hashing engine
  email = (fernet.decrypt(str.encode(data["email"]))).decode("utf-8") # decrypt the email

  if password_is_correct(username=username,password=password): # correct creds
    if int(verif_codes[email]["code"])==int(code):
      if round(time.time()) < verif_codes[email]["expires"]:
        del verif_codes[email]
        update_data(username=username,key="verified",value=True)
        return 'OK', 200
      else:
        del verif_codes[email]
        return 'Not Found', 404 # The code has expired
    else:
      return 'Forbidden', 403 # The code is invalid.
  else:
    return 'Unauthorized', 401 # invalid creds
  
  
def is_user_verified(token: str) -> tuple:
  username = parse_token(token)[1]
  password = parse_token(token)[0]
  if(username=="X"):
    return 'Precondition Failed', 412
  data = get_data(username=username)
  
  if password_is_correct(username=username,password=password): # correct creds
    verified: bool = data["verified"]
    if not verified:
      return 'Unauthorized',401
    return 'OK',200
# thats it, finally!