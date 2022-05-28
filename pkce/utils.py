
"########################"
"#   HELPER FUNCTIONS   #"
"########################"

import re
import base64
from os import urandom
import uuid

"""

make_code
short_code

"""

def make_code(n: int = 43):
	""" helper to make a urlsafe short code.
		
		EXAMPLES:
			>>> pkce.make_code()      #> 'RhHQthqhHC7D6uy29YMInnKzOck5Rg74s36lMZ4gplT'
			>>> pkce.make_code(60)    #> 'WAoBm21vEEIvUHIrtBgeBFdDSqjD0sFgAonIVWgwibrngosgpmMa3Sr3Mm0N'
			>>> pkce.make_code('')    #> 'FfNU2hejdM2vqKF2Ey0Wx05qEWA0vaYHELwpxcXciYpuLnmzeFnYQU3SaTOqcJtMyHlxmDO4pAflWbS8l010B7DxwQWFV9Mf2tpkxA1YuE7mS3hvA2tv0w1ey0vrvGTI'
			>>> pkce.make_code(False) #> 'jvDQtfK9b0LtEm2I3pZmHBTuIV4LkUsw2WAvwE4Iqpk7vnWc3Wj7IoGqslJiV9yC1XVdY0P3Tc21t0ne0KVCEB6XoYlKWjRjyqkG4ISX1aCXLtGOmczLl1IDs9ZS2oYJ'
			>>> pkce.make_code(0)     #> 'qP51XqUU5jf6C9aNMOy9xqNJFnE8voG6tVdLEHfznI9PZIqB8je7fnsQV2bZxHDlqib1oFym7tds0K6zQiZUqy56yBxrbkt0iJfDG6ISy5jZZ0mBbeG14FGQ5RoFz3lB'
			>>> pkce.make_code(10)    #> 'gOgGLjBAmffO7ytwtfRdL4Nqkf2SJ0cPs5BIIFWehEuwPm7bjsXknEHHLcd1zMECNTkOiEiZlgnf59qa7Osg3cL9cfEcCrvaZ5M59p4ufYp25INo96EhUCpZN3Q4RSiH'
			>>> pkce.make_code(1000)  #> 'uSnR4ZOJC7qX4jBl3iq78jDxgZgoEvN1jSBWgBOy8yaRx1VtgRnRj5DZmveuQdiqODw7cNPrKFstZNm3bEExEe0sPorBa9PSy5W3EdhiSyaKP9betvBw1eActMwswSi5'
			>>> pkce.make_code(None)  #> 'OPRzvCKeSY8Ucq4BErEQ4a7SwOa6eOu5nFmwmweqKr2eVW3QpR5k1QvPLbU5ktfakmMvFUmHRcNRZpkNesg3FSI53xT19G9Vxf2f1fGyZlFbmmj8exFFxiEML15aaJIL'
		
		REQUIRES:
			import re;import base64;from os import urandom
	"""
	n = 128 if not isinstance(n, int) else n
	n = 128 if not 43 <= n <= 128 else n
	short_code_raw = base64.urlsafe_b64encode(urandom(n*2)).decode('utf-8')
	short_code = re.sub('[^a-zA-Z0-9]+', '', short_code_raw)
	return short_code[:n]


def short_code():
	""" helper code to make a short code, used for state

		EXAMPLES:
			>>> import uuid
			>>> uuid.uuid4().hex #> 'ca1ecea7e6fb47ef8c306ebc51d326d4'
			>>> secrets.token_urlsafe(24) #> 'sPYPr1evEU0EpROcqCAKz4yiDB2EzVTa'

		REQUIRES:
			import secrets
			from uuid import uuid4 
	"""
	return secrets.token_urlsafe(24) #> 'sPYPr1evEU0EpROcqCAKz4yiDB2EzVTa'
	return uuid.uuid4().hex #> 'ca1ecea7e6fb47ef8c306ebc51d326d4'
