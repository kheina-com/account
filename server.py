from models import LoginRequest, CreateAccountRequest, ChangePasswordRequest
from starlette.middleware.trustedhost import TrustedHostMiddleware
from kh_common.exceptions import jsonErrorHandler
from fastapi.responses import UJSONResponse
from kh_common.auth import KhAuthMiddleware
from fastapi import FastAPI, Request
from account import Account


app = FastAPI()
app.add_exception_handler(Exception, jsonErrorHandler)
app.add_middleware(TrustedHostMiddleware, allowed_hosts={ 'localhost', '127.0.0.1', '*.kheina.com' })
app.add_middleware(KhAuthMiddleware, required=False)

account = Account()


@app.on_event('shutdown')
async def shutdown() :
	account.close()


@app.post('/v1/login')
async def v1Vote(req: Request, body: LoginRequest) :

	auth = await account.login(body.email, body.password, req.client.host)

	response = UJSONResponse(auth)
	response.set_cookie('kh_auth', auth['token_data']['token'], secure=True, httponly=True, samesite='lax')

	return response


@app.post('/v1/create_account')
async def v1Vote(req: LoginRequest) :
	return UJSONResponse(
		await account.createAccount(req.name, req.handle, req.email, req.password)
	)


@app.post('/v1/change_password')
async def v1Vote(req: ChangePasswordRequest) :
	return UJSONResponse(
		await account.changePassword(req.email, req.password, req.new_password)
	)


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
