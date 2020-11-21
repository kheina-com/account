from models import LoginRequest, CreateAccountRequest, ChangePasswordRequest
from kh_common.server import ServerApp, UJSONResponse
from fastapi import FastAPI, Request
from account import Account


app = ServerApp(auth=False)
account = Account()


@app.on_event('shutdown')
async def shutdown() :
	account.close()


@app.post('/v1/login')
async def v1Login(req: Request, body: LoginRequest) :

	auth = await account.login(body.email, body.password, req.client.host)

	response = UJSONResponse(auth)
	response.set_cookie('kh_auth', auth['token_data']['token'], secure=True, httponly=True, samesite='lax')

	return response


@app.post('/v1/create_account')
async def v1CreateAccount(req: CreateAccountRequest) :
	auth = await account.createAccount(req.name, req.handle, req.email, req.password)
	return UJSONResponse(auth, status_code=auth.get('status', 200))


@app.post('/v1/change_password')
async def v1ChangePassword(req: ChangePasswordRequest) :
	auth = await account.changePassword(req.email, req.password, req.new_password)
	return UJSONResponse(auth, status_code=auth.get('status', 200))


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
