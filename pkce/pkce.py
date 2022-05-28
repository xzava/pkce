""" PKCE - (Proof Key for Code Exchange or 'pixy') used in the Oauth 2.0 Authorization Code Grant

PKCE is used when network traffic could be monitored to prove a person who made a request is the same person.
ie a server will know its talking to the right person not a man in the middle.

Prove your relationship to a HTTP request by:
1. Creating a random password
2. Sending the hash of the password with your HTTP request (+ the hash method).
3. Then later sending the password for the third party server to compare to verify your relationship to the request.


Used in the Oauth 2.0 Authorization Code flow.

So you don't need to expose your client_id and client_secret


Docs
=========
https://datatracker.ietf.org/doc/html/rfc7636 - PKCE


Examples
=========
>>> import pkce
>>> pixy = pkce.generate()
Pixy(
	code_verifier='us3AnbgB73HRyQkcRlje5cZ7vqhLlPJl5yURbyuirpxnrWGnj6Lx_jI0s6n1Ty0Qn5eXmoaemg27Kpn5A9WMxV0U4mOSktyhCk1INOXQVFPGXftoKaSgxx7j-XcRaHur', 
	code_challenge='bS6E_EoQsxwhHVRH1xNfULenql5val38REP5KdOvM-8',
	code_challenge_method='S256'
)


# Auth server uses this code.
>>> pkce.solve(code_verifier, code_challenge, code_challenge_method)
True

>>> pkce.solve(**dict(pixy))
True

>>> pkce.solve(**pkce.generate().dict())
True


# https://datatracker.ietf.org/doc/html/rfc7636
Protocol ..........................................................8
  4.1. Client Creates a Code Verifier .............................8
  4.2. Client Creates the Code Challenge ..........................8
  4.3. Client Sends the Code Challenge with the
	   Authorization Request ......................................9
  4.4. Server Returns the Code ....................................9
	   4.4.1. Error Response ......................................9
  4.5. Client Sends the Authorization Code and the Code
	   Verifier to the Token Endpoint ............................10
  4.6. Server Verifies code_verifier before Returning the Tokens 


This specification adds additional parameters to the OAuth 2.0
Authorization and Access Token Requests, shown in abstract form in
Figure 2.

A. The client creates and records a secret named the "code_verifier"
  and derives a transformed version "t(code_verifier)" (referred to
  as the "code_challenge"), which is sent in the OAuth 2.0
  Authorization Request along with the transformation method "t_m".

B. The Authorization Endpoint responds as usual but records
  "t(code_verifier)" and the transformation method.

C. The client then sends the authorization code in the Access Token
  Request as usual but includes the "code_verifier" secret generated
  at (A).

D. The authorization server transforms "code_verifier" and compares
  it to "t(code_verifier)" from (B).  Access is denied if they are
  not equal.

An attacker who intercepts the authorization code at (B) is unable to
redeem it for an access token, as they are not in possession of the
"code_verifier" secret.


Info
=========

code verifier (private) 
  A cryptographically random string that is used to correlate the
  authorization request to the token request.

code challenge (public) 
  A challenge derived from the code verifier that is sent in the
  authorization request, to be verified against later.

code challenge method
  A method that was used to derive code challenge.

Base64url Encoding
  Base64 encoding using the URL- and filename-safe character set
  defined in Section 5 of [RFC4648], with all trailing '='
  characters omitted (as permitted by Section 3.2 of [RFC4648]) and
  without the inclusion of any line breaks, whitespace, or other
  additional characters.  (See Appendix A for notes on implementing
  base64url encoding without padding.)



Other methods:
https://www.stefaanlippens.net/oauth-code-flow-pkce.html


Resources:
https://blog.postman.com/pkce-oauth-how-to/
https://datatracker.ietf.org/doc/html/rfc6749  - OAuth 2.0
https://openid.net/specs/openid-connect-core-1_0.html  - OpenID Connect
https://www.iana.org/assignments/jwt/jwt.xhtml - jwt Claims


https://YOUR_DOMAIN/authorize?
	response_type=code&
	code_challenge=CODE_CHALLENGE&
	code_challenge_method=S256&
	client_id=YOUR_CLIENT_ID&
	redirect_uri=YOUR_CALLBACK_URL&
	scope=SCOPE&
	state=STATE


<a href="https://YOUR_DOMAIN/authorize?
  response_type=code&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=YOUR_CALLBACK_URL&
  scope=openid%20profile&
  state=xyzABC123">
  Sign In
</a>


curl --request POST \
  --url 'https://YOUR_DOMAIN/oauth/token' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=authorization_code \
  --data 'client_id=YOUR_CLIENT_ID' \
  --data code_verifier=YOUR_GENERATED_CODE_VERIFIER \
  --data code=YOUR_AUTHORIZATION_CODE \
  --data 'redirect_uri=https://YOUR_APP/callback'

"""

# Another version.
# https://github.com/lepture/authlib/blob/master/authlib/oauth2/rfc7636/challenge.py

import secrets
import hashlib
import base64
import re
from os import getenv
from dataclasses import dataclass, asdict, astuple
from copy import deepcopy

CODE_VERIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9\-._~]{43,128}$')
FERNET_KEY = getenv('FERNET_KEY', '').encode()
VERBOSE_PKCE = getenv('VERBOSE_PKCE', '')
# APPLICATION_NAME="auth_server"

# from cryptography.fernet import Fernet
# assert FERNET_KEY, "requires a FERNET_KEY env --> from cryptography.fernet import Fernet;Fernet.generate_key().decode()"

"""

EXAMPLES:

	>>> import pkce
	>>> pkce.generate()
	Pixy(
		code_verifier='JEsUBbjgXB4szfBn7-LJ7vOir1t_rqBX8mLDHO-yeVdipl9PlS2gvRAPQsldb8MtkVZ_azGtqtQfn6dvRPPlgsWHDLr3HcLjEuuW9yq58Mgj7XW0lhwImt1smVdjF879',
		code_challenge='C1MzkLRi_rKyRnxFkWa-5qfvuohwo5r3ufug4waI8Cw',
		code_challenge_method='S256'
	)

	>>> pixy = pkce.generate()
	>>> pixy.code_verifier
	'B98x18KCZsXdXoBKctzVnTmQ9_KaLQVSir6aL45zi1GuX_1MjBrfLb1DDAF4VBrRh4k2_-Fd9TTpSMWwYQki5P-bIfRoHsANtkqQofHe0xvut3SjQAzronvoIqlgftBl'
	>>> pixy.code_challenge
	'UJFi4jeGi8t9IiYecJm7-1JWklXMDIKOaDHkYXqCw0k'
	>>> pixy.code_challenge_method
	'S256'

"""

def verbose(*args):
	"export VERBOSE_PKCE=1"
	if VERBOSE_PKCE:
		print(*args)


"###################"
"#     MODELS      #"
"###################"


@dataclass
class Pixy:
	""" PKCE wrapper class
	"""
	code_verifier: str
	code_challenge: str
	code_challenge_method: str
	
	def dict(self):
		return asdict(self)
	
	def tuple(self):
		return astuple(self)
	
	def __iter__(self):
		return iter(self.__dict__.items())

	def __cmp__(self, dict_):
	    return self.__cmp__(self.__dict__, dict_)


"###################"
"#     ERRORS      #"
"###################"


class TransformAlgorithm(Exception):
	""" The system can not accept this transformation method.
	"""
	response = {"error": "invalid_request", "error_description": "transform algorithm not supported"}


class VerifierLength(Exception):
	""" 'code_verifier' must be between 43 and 128
	"""
	response = {"error": "invalid_request", "error_description": "verifier length is out of spec"}


class MissingChallenge(Exception):
	""" 'code challenge required'
	"""
	response = {"error": "invalid_request", "error_description": "code challenge required"}


class NotEqual(Exception):
	""" code_verifier failed to verify code_challenge
	"""
	response = {"error": "invalid_grant", "error_description": "code verifier failed"}


class InvalidRequestError(Exception):
	""" 'code_verifier' must be between 43 and 128
	"""
	response = {"error": "invalid_request", "error_description": "verifier is out of spec"}


"###################"
"#     HELPERS     #"
"###################"


def _check_length(length=None):
	""" Check 'code_verifier' length is between 43 and 128 or throw error.
	"""
	if isinstance(length, (int, float)):
		if 43 <= length <= 128:
			return True
	raise VerifierLength(f"Too short: 'code_verifier' must be between 43 and 128")


def _check_verifier(code_verifier=None):
	""" Check verifier is correct format
	"""
	# CODE_VERIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9\-._~]{43,128}$')
	if isinstance(code_verifier, str):
		if CODE_VERIFIER_PATTERN.match(code_verifier):
			return True
	raise InvalidRequestError('Invalid "code_verifier"')


def _check_challenge(code_challenge=None):
	""" Check a challenge is the right type
	"""
	if isinstance(code_challenge, str):
		return True
	raise MissingChallenge('PKCE is required')


def _check_method(code_challenge_method=None, accepted_methods=None):
	""" Check a method is accepted
	"""
	if code_challenge_method in (accepted_methods or ['S256', 'plain']):
		return True
	raise TransformAlgorithm('transform algorithm not supported')



"################"
"#     CORE     #"
"################"


def generate(code_challenge_method='S256', length: int=128) -> Pixy:
	""" Return random PKCE-compliant code verifier and code challenge.

		Send the code_challenge (hashed random string) to the server,
		then later send the code_verifier (random string) to confirm your relationship to the orginal request 

		'code_verifier' is a random password.
		'code_challenge' is a hash of the password.
		'code_challenge_method' is a hash method DEFAULT:S256 
		
		EXAMPLE:
		>>> pixy = pkce.generate()
		>>> pixy.code_verifier
		'qbJFmoC11ZX90flBDBz4Ncu1CGsYoXKrLEJfoMoOy3T-OIW-r4GjgFbgcqbp3-a0VxyZfIY5n9af0xbPjkuo9wF8198ekqKNJ15l4CoHTykb3VcC9WNOXPyiRDg6LSuc'
		>>> pixy.code_challenge
		'4q6FoldagtNEDSFH7qiXRCPsW7HEPa6ozcT872VEHcw'
		>>> pixy.code_challenge_method
		'S256'
		
		NOTE: 'code_verifier' must be length between 43 and 128 --> "^[a-zA-Z0-9-._~]{43,128}$"
	"""
	if code_challenge_method == "plain":
		print("WARNING: The 'plain' method is depreciated and SHOULD NOT be used.")
	code_verifier = make_verifier(length)
	code_challenge = make_challenge(code_verifier, code_challenge_method)

	return Pixy(
		code_verifier=code_verifier,
		code_challenge=code_challenge,
		code_challenge_method=code_challenge_method,
	)
	# return code_verifier, code_challenge, code_challenge_method


def make_verifier(length: int=128) -> str:
	""" This is the password or a random string called 'code_verifier'

		NOTE: length between 43 and 128 --> "^[a-zA-Z0-9-._~]{43,128}$"
		NOTE: len(secrets.token_urlsafe(96)) == 128
	""" 
	_check_length(length)
	code_verifier = secrets.token_urlsafe(96)[:length]
	return code_verifier


def make_challenge(code_verifier: str, code_challenge_method="S256") -> str:
	""" Create the challenge by hashing the verifier
		
		ie return the hash the password (code_verifier)
		Return the PKCE-compliant code challenge for a given verifier.

	"""
	def sha256_method(code_verifier: str) -> str:
		""" This is the default method to generate a code_challenge using SHA256

			BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
			
			NOTE: https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
		"""
		hashed_verifier = hashlib.sha256(code_verifier.encode('ascii')).digest()
		encoded_verifier = base64.urlsafe_b64encode(hashed_verifier)
		code_challenge = encoded_verifier.decode('ascii').rstrip('=') # removing trailing '=' as per spec
		return code_challenge #> sG28713i0hoCxpJvEpQi2lgPm14Fz6jYf8V5UUg7J9A

	challenge_function = {
		"S256": sha256_method,
		"plain": lambda code_verifier: code_verifier, #> no tranformations is done
	}

	_check_verifier(code_verifier)
	_check_method(code_challenge_method)
	
	code_challenge = challenge_function.get(code_challenge_method)(code_verifier)
	return code_challenge


def solve(code_verifier=None, code_challenge=None, code_challenge_method="plain") -> bool:
	""" Solve code_challenge by hashing code_verifier and safly comparing strings. 
		default solve method is 'plain' as per the spec (default generate method is S256)
	"""
	try:
		_check_verifier(code_verifier) #> InvalidRequestError
		_check_challenge(code_challenge) #> MissingChallenge
		_check_method(code_challenge_method) #> TransformAlgorithm
		
		if secrets.compare_digest(make_challenge(code_verifier, code_challenge_method), code_challenge) is True:
			return True

		raise NotEqual('Could not solve')
		
	except TransformAlgorithm as e:
		# return {"error": "invalid_request", "error_description": "transform algorithm not supported"}
		return e.response

	except MissingChallenge as e:
		# return {"error": "invalid_request", "error_description": "code challenge required"}
		return e.response

	except NotEqual as e:
		# return {"error": "invalid_grant", "error_description": "code_challenge failed"}
		return e.response

	except InvalidRequestError as e:
		# return {"error": "invalid_request", "error_description": "verifier is out of spec"}
		return e.response
	
	except Exception as e:
		verbose(e)
		return {"error": "invalid_request", "error_description": "unknown error"}






###########################
###########################
###########################
###########################
###########################



# create_auth_code(challenge, method)
def create_auth_code(**kwargs):
	""" Create a auth code to send back to the client.
		encrypt this auth code with the 'code_challenge' and 'code_challenge_method'

		code: a temporary code that may only be exchanged once and expires 5 minutes after issuance.
	"""
	from uuid import uuid4
	from jose import jwt
	from cryptography.fernet import Fernet
	assert FERNET_KEY, "requires a FERNET_KEY env --> from cryptography.fernet import Fernet;Fernet.generate_key().decode()"
	
	f = Fernet(FERNET_KEY)
	# >>> pip install cryptography
	# >>> from cryptography.fernet import Fernet
	# >>> key = Fernet.generate_key() #> b'iN54fNs-JzmP7IjO3qoPSCcdo-739wWRTnP9yL8ioy0='
	# >>> f = Fernet(key)
	# >>> token = f.encrypt(b"my deep dark secret")
	# >>> token
	# b'...'
	# >>> f.decrypt(token)
	# b'my deep dark secret'

	# to_encode = kwargs.copy()
	to_encode = deepcopy(kwargs)
	# {
	#  'response_type': 'code',
	#  'code_challenge': '8DYG5kCYPIRgohDiacrdNjvKJcSZZw5EcLWSy4V0PVY',
	#  'code_challenge_method': 'S256',
	#  'client_id': 'mrsimple',
	#  'redirect_uri': 'http://127.0.0.1:5007/auth/callback',
	#  'scope': 'openid profile',
	#  'state': '5PcvTI9DSWD3y7ad8JGncUlZZGDjue1NyWB4FkblstE',
	#  'nonce': 'xQ9dPSTiqrCnUsFRBKwfAewWDZIhbvWfwpeYSKdByta'
	# }
	audience="auth_code"
	timenow = jwt.datetime.utcnow()
	to_encode.update({'exp': timenow + jwt.timedelta(minutes=5)}) # short lived code tokens.
	to_encode.update({'iat': timenow})
	to_encode.update({'aud': audience})
	# to_encode.update({'iss': "auth_server"})
	# to_encode.update({'sub': "auth_code"})
	# to_encode.update({'typ': "auth_code"})
	# to_encode.update({'jti': str(uuid4())})

	token = jwt.encode(to_encode, FERNET_KEY.decode(), 'HS256')
	verbose(token)
	encrypted_code = f.encrypt(token.encode()).decode()
	verbose('encrypted_code', encrypted_code)
	return encrypted_code


def load_auth_code(auth_code, audience="auth_code"):
	""" Create a auth code to send back to the client.
		encrypt this auth code with the 'code_challenge' and 'code_challenge_method'

		This requires extra installs
		pip install python-jose[cryptography]
	"""
	try:
		from jose import jwt
		from cryptography.fernet import Fernet
		assert FERNET_KEY, "requires a FERNET_KEY env --> from cryptography.fernet import Fernet;Fernet.generate_key().decode()"
		f = Fernet(FERNET_KEY)

		token = f.decrypt(auth_code.encode()).decode()
		# token = f.decrypt(enc.encode()).decode()

		# print(FERNET_KEY)
		payload = jwt.decode(token, FERNET_KEY.decode(), algorithms=['HS256'], audience="auth_code")
		assert payload.get('aud') == audience, 'Wrong aud'
		return payload
	except Exception as e:
		verbose(e)
		raise e
		# decryption error
		# error spliting
		# unpacking error
		# auth_code missing error, type error
		"assume no pkce and return unchanged auth_code"





