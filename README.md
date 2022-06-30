> README.md


# PKCE 'Proof Key Code Exchange' 

[pkce](https://github.com/xzava/pkce) 'Proof Key Code Exchange' or pronounced 'pixy' is a python PKCE library.

This library deals with the creation and verification of PKCE codes, ie: `OAuth 2.0 'Code flow'`

> - Described here: [Official PKCE Spec](https://datatracker.ietf.org/doc/html/rfc7636)
> - Here: [oauth.net](https://oauth.net/2/pkce/)
> - Here: [auth0.com](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)
> - And here: [xero.com](https://developer.xero.com/documentation/guides/oauth2/pkce-flow/)

<p align="center">
  <img height="200px" src="https://raw.githubusercontent.com/xzava/pkce/main/docs/pixy.png">
</p>


### Installation

```bash
pip install git+https://github.com/xzava/pkce.git --upgrade
```

### Examples

> - No dependencies for the client 
> - Only one optional import for the server. `pip install python-jose[cryptography]`

```python

>>> import pkce
>>> pkce.generate()
Pixy(
  code_verifier='JEsUBbjgXB4szfBn7-LJ7vOir1t_rqBX8mLDHO-yeVdipl9PlS2gvRAPQsldb8MtkVZ_azGtqtQfn6dvRPPlgsWHDLr3HcLjEuuW9yq58Mgj7XW0lhwImt1smVdjF879',
  code_challenge='C1MzkLRi_rKyRnxFkWa-5qfvuohwo5r3ufug4waI8Cw',
  code_challenge_method='S256'
)
```


#### Extras

```python
>>> pixy = pkce.generate()
>>> pixy.code_verifier  #> a password..
'B98x18KCZsXdXoBKctzVnTmQ9_KaLQVSir6aL45zi1GuX_1MjBrfLb1DDAF4VBrRh4k2_-Fd9TTpSMWwYQki5P-bIfRoHsANtkqQofHe0xvut3SjQAzronvoIqlgftBl'
>>> pixy.code_challenge #> a hash of the password..
'UJFi4jeGi8t9IiYecJm7-1JWklXMDIKOaDHkYXqCw0k'
>>> pixy.code_challenge_method #> the hash method use to hash the password..
'S256'

>>> pkce.solve(pixy.code_verifier, pixy.code_challenge, pixy.code_challenge_method)
True

```

#### Errors & Success
```python

>>> pkce.solve(**dict(pkce.generate())) 
True

>>> pkce.solve("password123", pixy.code_challenge, pixy.code_challenge_method)
{'error': 'invalid_request', 'error_description': 'verifier is out of spec'}

>>> pkce.solve("JEsUBbjgXB4szfBn7-LJ7vOir1t_rqBX8mLDHO-yeVdipl9PlS2gvRAPQsldb8MtkVZ_azGtqtQfn6dvRPPlgsWHDLr3HcLjEuuW9yq58Mgj7XW0lhwImt1smVdjF879", pixy.code_challenge, pixy.code_challenge_method)
{'error': 'invalid_grant', 'error_description': 'code verifier failed'}

>>> pkce.solve('B98x18KCZsXdXoBKctzVnTmQ9_KaLQVSir6aL45zi1GuX_1MjBrfLb1DDAF4VBrRh4k2_-Fd9TTpSMWwYQki5P-bIfRoHsANtkqQofHe0xvut3SjQAzronvoIqlgftBl', pixy.code_challenge, pixy.code_challenge_method)
True

```


### STEPS:

1. Client creates the pixy object,
2. They save it in a database/keyvalue store, they need it later.
3. Client sends `Code Challenge` to the server to say, 'I want a `Authorization Code`, remember me for later'
4. Server creates a `Authorization Code` and saves both `Authorization Code` and `Code Challenge`, they need it later. 
5. Server sends the `Authorization Code` they created and the `Code Challenge` from the client
6. Client uses the `Code Challenge`  as a key to get the `Code Verifier` that they saved somewhere
7. Client returns all three codes to the server. `Code Verifier`, `Code Challenge`, `Authorization Code`
8. Server checks the `Authorization Code` is unused and valid, then checks the `Code Verifier` hashes into the `Code Challenge`
9. Server says thanks I trust its you who made the request, here is the `Authorization Code` you requested.


<p align="center">
  <img src="https://raw.githubusercontent.com/xzava/pkce/main/docs/pkce.png">
</p>


## Notes:

- Its possible for the server to encrypt all information inside the `Authorization Code` and pass that back to the client, avoid a database round trip.
The sever should still check for expiry and token reuse, the latter still requires database.

- I have also seen JavaScript web apps store information encrypted in the headers, how you store this information is up to you.

- I store it in a key/value database (dynamodb using pynamite)


### PROTOCOL

```
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
```


## Functions for Client Server:

```python

pkce.generate()
pkce.make_verifier()
pkce.make_challenge()


```


## Functions for Auth Server:

```python

pkce.solve()
pkce.create_auth_code()
pkce.load_auth_code()
pkce.compare() #> Compare Authorization Code's

```

`create_auth_code()` and `load_auth_code()` encrypt and decrypt the PKCE information into the `Authorization Code`

> requires a FERNET_KEY env --> from cryptography.fernet import Fernet;Fernet.generate_key().decode()

Feel free to use your own method to store this information, in stateless or statefull way.

## UTILS

```python

# Used for creating `Authorization Code` or 'Nonce'

>>> pkce.make_code()  #> 'RhHQthqhHC7D6uy29YMInnKzOck5Rg74s36lMZ4gplT'
>>> pkce.short_code() #> 'sPYPr1evEU0EpROcqCAKz4yiDB2EzVTa'

```

## Whats the point?

- [Official PKCE Spec](https://datatracker.ietf.org/doc/html/rfc7636)
- [wtf-is-pkce-and-why-should-you-care](https://dzone.com/articles/what-is-pkce)


## Donate

> Consider donating if you find this as useful as I do. 

Making this free and useful is the right thing to do.

[<td style="text-align:center"> <img alt="Buymeacoffee logo" src="https://cdn.buymeacoffee.com/assets/img/email-template/bmc-new-logo.png" style="max-width:100%;width:200px" class="CToWUd"> </td>](https://www.buymeacoffee.com/kaurifund)



## Check out my other open source libraries

- [pynamite](https://datatracker.ietf.org/doc/html/rfc7636) Python dynamodb library
- [jsonify](https://datatracker.ietf.org/doc/html/rfc7636) Flask json UI for interactive API's


<!-- 
```

[Create a venv first]

git clone https://github.com/xzava/pkce.git
cd pkce

python setup.py develop
python setup.py develop pkce[testing]

pip install -r requirements_dev.txt


python -m pytest


python setup.py develop --uninstall


python setup.py develop easy_install pkce[testing]
```


```
pip install git+https://github.com/xzava/pkce.git --upgrade
pip uninstall pkce

python setup.py develop --uninstall

``` -->
