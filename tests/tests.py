""" Tests
	
	pip install pytest
	python -m pytest tests/tests.py

"""

import pkce
from dataclasses import asdict

# export FERNET_KEY='5ZQ-Wyo9oWOq4u_w9UWNRbRFr41CL3BJZBg38T2EEhc='

def test_generate():
	# verifier, challenge, method = pkce.generate()

	pixy = pkce.generate()

	verifier = pixy.code_verifier
	challenge = pixy.code_challenge
	method = pixy.code_challenge_method

	pkce._check_verifier(verifier) 
	pkce._check_challenge(challenge) 
	pkce._check_method(method)

	pkce.solve(**asdict(pkce.generate()))
	# pkce.solve(**asdict(pkce.generate('plain')))
	pkce.solve(verifier, challenge, method)

	# pkce.NotEqual: Could not solve
	# assert pkce.solve(verifier, challenge, 'plain') == {'error': 'invalid_grant', 'error_description': 'code_challenge failed'}
	assert pkce.solve(verifier, challenge) == {"error": "invalid_grant", "error_description": "code verifier failed"}
	assert pkce.solve(verifier +'hello', challenge) == {'error': 'invalid_request', 'error_description': 'verifier is out of spec'}
	assert pkce.solve(verifier[:-5], challenge) == {"error": "invalid_grant", "error_description": "code verifier failed"}
	assert pkce.solve(verifier, challenge +'hello') == {"error": "invalid_grant", "error_description": "code verifier failed"}
	assert pkce.solve(verifier) == {'error': 'invalid_request', 'error_description': 'code challenge required'}
	assert pkce.solve(challenge) == {'error': 'invalid_request', 'error_description': 'code challenge required'}
	assert pkce.solve(challenge, verifier) == {"error": "invalid_grant", "error_description": "code verifier failed"}
	assert pkce.solve(None, None, None) == {'error': 'invalid_request', 'error_description': 'verifier is out of spec'}
	assert pkce.solve(verifier, challenge, None) == {'error': 'invalid_request', 'error_description': 'transform algorithm not supported'}
	assert pkce.solve(verifier, challenge, 'hello') == {'error': 'invalid_request', 'error_description': 'transform algorithm not supported'}

	auth_code = pkce.create_auth_code(code_challenge=challenge, code_challenge_method=method)
	# 'gAAAAABhLYVZX-swd9VCJusluAaJfWnI8VJpv2r6oprYaovbHi8Sk9HRMkbo1iINFXitKnC6H0FuBNqU7MXt_uGWuNmYk2rGeOK2X9xAChDb6BzPXgZXilj0V24NEiT_Rs-bFRjcyuHlFEgsEbDALG8EscD4RjMEoA=='
	pkce.load_auth_code(auth_code)
	pkce.load_auth_code(pkce.create_auth_code(code_challenge=challenge, code_challenge_method=method))
	# ('A4jYPUmFHseJg2YPEkCqaMHnX3l3e4KPzDb88MyPna8', 'S256')


def test():
	""" import pkce;pkce.test()
	>>> makkeee()
	challenge --> new_method: YjA2ZGJjZWY1ZGUyZDIxYTAyYzY5MjZmMTI5NDIyZGE1ODBmOWI1ZTA1Y2ZhOGQ4N2ZjNTc5NTE0ODNiMjdkMA
	challenge --> old_method: sG28713i0hoCxpJvEpQi2lgPm14Fz6jYf8V5UUg7J9A

	"""
	# verifier, challenge, method = generate(code_challenge_method='S256_hexdigest')
	generate = pkce.generate
	solve = pkce.solve
	make_challenge = pkce.make_challenge

	pixy = generate(code_challenge_method='S256')

	verifier = pixy.code_verifier
	challenge = pixy.code_challenge
	method = pixy.code_challenge_method

	print('')
	print(f'verifier: {verifier}')
	print(f'challenge: {challenge}')
	print(f'method: {method}')
	print(f'solve: {solve(verifier, challenge, method)}')
	print('')


	pixy = generate(code_challenge_method='S256')

	verifier = pixy.code_verifier
	challenge = pixy.code_challenge
	method = pixy.code_challenge_method
	# verifier, challenge, method = generate()
	print('')
	print(f'verifier: {verifier}')
	print(f'challenge: {challenge}')
	print(f'method: {method}')
	print(f'solve: {solve(verifier, challenge, method)}')
	print('')


	assert solve(verifier, challenge, 'S256')
	assert solve(verifier, make_challenge(verifier), 'S256')
	assert solve(**asdict(generate()))
	assert solve(verifier, make_challenge(verifier, 'S256'), 'S256')
	assert solve(**asdict(generate()))
	# assert solve(verifier, make_challenge(verifier, 'S256_hexdigest'), 'S256_hexdigest')
	assert solve(verifier, make_challenge(verifier, 'S256'), 'S256')
	assert solve(**asdict(generate()))
	assert solve(**asdict(generate('plain')))
	


	transform_algorithm = {"error": "invalid_request", "error_description": "transform algorithm not supported"}
	verifier_length = {"error": "invalid_request", "error_description": "verifier is out of spec"}
	missing_challenge = {"error": "invalid_request", "error_description": "code challenge required"}
	pkce_fail = {"error": "invalid_grant", "error_description": "code verifier failed"}
	# pkce_fail = {"error": "invalid_grant", "error_description": "code_challenge failed"}


	try:
		# This does not have an error response json because the error happens in generate,
		# which is a client side function, compared to solve which is used by the server.
		solve(**asdict(generate(length=10)))
	except pkce.VerifierLength as e:
		print("VerifierLength error caught in generate()")

	try:
		generate(code_challenge_method="hello")
	except pkce.TransformAlgorithm as e:
		print("TransformAlgorithm error caught in generate()")


	assert solve(verifier, make_challenge(verifier), 'a') == transform_algorithm #> "TransformAlgorithm error caught"

	assert solve(verifier, make_challenge(verifier)) == pkce_fail #> "NotEqual error caught"

	assert solve(verifier, None, 'S256') == missing_challenge #> "MissingChallenge error caught"

	assert solve(verifier, 'NotEqual', 'S256') == pkce_fail #> "NotEqual error caught"

	assert solve(verifier, 'S256') == pkce_fail #> "NotEqual error caught"

	assert solve('hello', 'hii') == verifier_length #> "verifier too short"

	assert solve(verifier, verifier)

	assert solve(verifier, verifier, 'plain')

	assert solve(verifier, challenge, 'plain') == pkce_fail

	assert solve(verifier, challenge) == pkce_fail



	assert solve(verifier, True, 'S256') == missing_challenge
	assert solve(verifier, False, 'S256') == missing_challenge

	# print(solve(False, False, 'S256'))

	assert solve(False, False, 'S256') == verifier_length
	assert solve(True, False, 'S256') == verifier_length
	assert solve(None, False, 'S256') == verifier_length


	print('All tests passed')