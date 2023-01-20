from fastapi.responses import UJSONResponse
from kh_common.auth import Scope
from kh_common.config.credentials import fuzzly_client_token
from kh_common.datetime import datetime
from kh_common.server import Request, ServerApp

from account import Account, auth_client
from fuzzly_account.constants import AuthHost
from fuzzly_account.models import BotCreateRequest, BotCreateResponse, BotLoginRequest, ChangeHandle, ChangePasswordRequest, CreateAccountRequest, FinalizeAccountRequest, LoginRequest, LoginResponse


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


@app.on_event('shutdown')
async def shutdown() :
	account.close()


@app.post('/v1/login', response_model=LoginResponse)
async def v1Login(req: Request, body: LoginRequest) :
	auth = await account.login(body.email, body.password, req)

	response = UJSONResponse(auth)

	if auth.token.token :
		expires = auth.token.expires - datetime.now()
		response.set_cookie('kh-auth', auth.token.token, secure=True, httponly=True, samesite='strict', expires=int(expires.total_seconds()))

	return response


@app.post('/v1/create', status_code=204)
async def v1CreateAccount(body: CreateAccountRequest) :
	await account.createAccount(body.email, body.name)


@app.post('/v1/finalize', response_model=LoginResponse)
async def v1FinalizeAccount(req: Request, body: FinalizeAccountRequest) :
	auth = await account.finalizeAccount(body.name, body.handle, body.password, body.token, req.client.host)

	response = UJSONResponse(auth)

	if auth.token.token :
		expires = auth.token.expires - datetime.now()
		response.set_cookie('kh-auth', auth.token.token, secure=True, httponly=True, samesite='strict', expires=int(expires.total_seconds()))

	return response


@app.post('/v1/change_password', status_code=204)
async def v1ChangePassword(req: Request, body: ChangePasswordRequest) :
	await req.user.verify_scope(Scope.user)
	await account.changePassword(body.email, body.password, body.new_password)


@app.post('/v1/change_handle', status_code=204)
async def v1ChangeHandle(req: Request, body: ChangeHandle) :
	await req.user.verify_scope(Scope.user)
	await account.changeHandle(req.user, body.handle)


@app.post('/v1/bot_login', response_model=LoginResponse)
async def v1BotLogin(body: BotLoginRequest) :
	# this endpoint does not require auth
	return await auth_client.bot_login(body.dict())


@app.post('/v1/bot_create', response_model=BotCreateResponse)
async def v1BotCreate(req: Request, body: BotCreateRequest) :
	await req.user.verify_scope(Scope.user)
	return await auth_client.bot_create(body.dict())


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
