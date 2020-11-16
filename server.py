from models import LoginRequest
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

	auth = await account.login(body.email, body.password)

	response = UJSONResponse(auth)
	response.set_cookie('kh_auth', auth['token'], secure=True, httponly=True, samesite='lax')

	return response


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='0.0.0.0', port=5004)
