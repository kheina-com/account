from models import LoginRequest, CreateAccountRequest, ChangePasswordRequest, FinalizeAccountRequest
from kh_common.server import Request, ServerApp, UJSONResponse
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
	auth = await account.createAccount(req.name, req.email)
	return Response(None, status_code=204)


@app.post('/v1/finalize')
async def v1CreateAccount(req: FinalizeAccountRequest) :
	auth = await account.finalizeAccount(req.name, req.handle, req.password, req.token)
	return UJSONResponse(auth, status_code=auth.get('status', 200))


@app.post('/v1/change_password')
async def v1ChangePassword(req: ChangePasswordRequest) :
	auth = await account.changePassword(req.email, req.password, req.new_password)
	return UJSONResponse(auth, status_code=auth.get('status', 200))


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
