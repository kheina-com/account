from models import ChangeHandle, ChangePasswordRequest,  CreateAccountRequest, FinalizeAccountRequest, LoginRequest
from kh_common.server import NoContentResponse, Request, ServerApp
from jmespath import compile as jmes_compile
from fastapi.responses import UJSONResponse
from account import Account
from time import time


app = ServerApp(
	auth_required = False,
	allowed_hosts = [
		'localhost',
		'127.0.0.1',
		'*.kheina.com',
		'kheina.com',
		'*.fuzz.ly',
		'fuzz.ly',
	],
	allowed_origins = [
		'localhost',
		'127.0.0.1',
		'dev.kheina.com',
		'kheina.com',
		'dev.fuzz.ly',
		'fuzz.ly',
	],
)
account = Account()
token_jmespath = jmes_compile('token_data.token')
expires_jmespath = jmes_compile('token_data.expires')


@app.on_event('shutdown')
async def shutdown() :
	account.close()


@app.post('/v1/login')
async def v1Login(req: Request, body: LoginRequest) :
	auth = await account.login(body.email, body.password, req)
	token = token_jmespath.search(auth)

	response = UJSONResponse(auth, status_code=auth.get('status', 200))
	if token :
		expires = expires_jmespath.search(auth) - time()
		response.set_cookie('kh-auth', token, secure=True, httponly=True, samesite='strict', expires=expires, domain='.fuzz.ly')

	return response


@app.post('/v1/create')
async def v1CreateAccount(req: CreateAccountRequest) :
	await account.createAccount(req.email, req.name)
	return NoContentResponse


@app.post('/v1/finalize')
async def v1FinalizeAccount(req: Request, body: FinalizeAccountRequest) :
	auth = await account.finalizeAccount(body.name, body.handle, body.password, body.token, req.client.host)
	token = token_jmespath.search(auth)

	response = UJSONResponse(auth, status_code=auth.get('status', 200))
	if token :
		response.set_cookie('kh-auth', token, secure=True, httponly=False, samesite='strict')

	return response


@app.post('/v1/change_password')
async def v1ChangePassword(req: ChangePasswordRequest) :
	auth = await account.changePassword(req.email, req.password, req.new_password)
	return UJSONResponse(auth, status_code=auth.get('status', 200))


@app.post('/v1/change_handle')
async def v1ChangeHandle(req: Request, body: ChangeHandle) :
	req.user.authenticated()
	account.changeHandle(req.user, body.handle)
	return NoContentResponse


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
