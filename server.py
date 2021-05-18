from models import ChangeHandle, ChangePasswordRequest,  CreateAccountRequest, FinalizeAccountRequest, LoginRequest
from kh_common.server import NoContentResponse, Request, ServerApp, UJSONResponse
from jmespath import compile as jmes_compile
from fastapi.responses import Response
from account import Account


app = ServerApp(auth_required=False)
account = Account()
token_jmespath = jmes_compile('token_data.token')


@app.on_event('shutdown')
async def shutdown() :
	account.close()


@app.post('/v1/login')
async def v1Login(req: Request, body: LoginRequest) :
	auth = await account.login(body.email, body.password, req.client.host)

	response = UJSONResponse(auth, status_code=auth.get('status', 200))
	response.set_cookie('kh-auth', token_jmespath.search(auth), secure=True, httponly=False, samesite='strict')

	return response


@app.post('/v1/create')
async def v1CreateAccount(req: CreateAccountRequest) :
	await account.createAccount(req.name, req.email)
	return NoContentResponse


@app.post('/v1/finalize')
async def v1FinalizeAccount(req: FinalizeAccountRequest) :
	auth = await account.finalizeAccount(req.name, req.handle, req.password, req.token, req.client.host)

	response = UJSONResponse(auth, status_code=auth.get('status', 200))
	response.set_cookie('kh-auth', token_jmespath.search(auth), secure=True, httponly=False, samesite='strict')

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
