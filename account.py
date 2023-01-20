import asyncio
from re import IGNORECASE
from re import compile as re_compile

from kh_common.auth import KhUser, browserFingerprint, verifyToken
from kh_common.client import Client
from kh_common.config.constants import environment
from kh_common.config.credentials import fuzzly_client_token
from kh_common.email import Button, sendEmail
from kh_common.exceptions.http_error import BadRequest, Conflict, HttpError, HttpErrorHandler
from kh_common.gateway import Gateway
from kh_common.hashing import Hashable
from kh_common.models.user import User
from kh_common.server import Request
from kh_common.sql import SqlInterface
from kh_common.utilities.json import json_stream
from psycopg2.errors import UniqueViolation

from fuzzly_account.constants import AuthHost
from fuzzly_account.models import LoginResponse, TokenResponse


class AuthClient(Client) :

	_login: Gateway = Gateway(AuthHost + '/v1/bot_login', LoginResponse, 'POST')

	def __init__(self: 'AuthClient', *a, **kv) :
		super().__init__(*a, **kv)
		asyncio.run(auth_client.start())
		self.login: Gateway = self.authenticated(Gateway(AuthHost + '/v1/login', LoginResponse, 'POST'))
		self.sign: Gateway = self.authenticated(Gateway(AuthHost + '/v1/sign_data', TokenResponse, 'POST'))
		self.create: Gateway = self.authenticated(Gateway(AuthHost + '/v1/create', LoginResponse, 'POST'))
		self.change_password: Gateway = self.authenticated(Gateway(AuthHost + '/v1/change_password', decoder=None))
		self.bot_login: Gateway = Gateway(AuthHost + '/v1/bot_login', LoginResponse, 'POST')
		self.bot_create: Gateway = self.authenticated(Gateway(AuthHost + '/v1/bot_create', BotCreateResponse, 'POST'))

auth_client: AuthClient = AuthClient(fuzzly_client_token)


class Account(SqlInterface, Hashable) :

	HandleRegex = re_compile(r'^[a-zA-Z0-9_]{5,}$')
	EmailRegex = re_compile(r'^(?P<user>[A-Z0-9._%+-]+)@(?P<domain>[A-Z0-9.-]+\.[A-Z]{2,})$', flags=IGNORECASE)
	VerifyEmailText = "Finish creating your new account at fuzz.ly by clicking the button below. If you didn't make this request, you can safely ignore this email."
	VerifyEmailSubtext = 'fuzz.ly does not store your private information, including your email. You will not receive another email without directly requesting it.'
	AccountCreateKey = 'create-account'
	AccountRecoveryKey = 'recover-account'


	def __init__(self: 'Account') :
		Hashable.__init__(self)
		SqlInterface.__init__(self)
		self._auth_timeout = 30

		if environment.is_prod() :
			self._finalize_link = 'https://fuzz.ly/account/finalize?token={token}'
			self._recovery_link = 'https://fuzz.ly/account/recovery?token={token}'

		else :
			self._finalize_link = 'https://dev.fuzz.ly/account/finalize?token={token}'
			self._recovery_link = 'https://dev.fuzz.ly/account/recovery?token={token}'


	def _validateEmail(self: 'Account', email: str) :
		email = Account.EmailRegex.search(email)
		if not email :
			raise BadRequest('the given email is invalid.')
		return email.groupdict()


	def _validatePassword(self: 'Account', password: str) :
		if len(password) < 10 :
			raise BadRequest(f'the provided password (length {len(password)}) is invalid. passwords must be at least 10 characters in length.')


	def _validateHandle(self: 'Account', handle: str) :
		if not Account.HandleRegex.fullmatch(handle) :
			raise BadRequest(f'the provided handle: {handle}, is invalid. handles must be at least 5 characters in length.')


	async def fetchUserByEmail(self: 'Account', email: str) -> User :
		data = await self.query_async()


	@HttpErrorHandler('logging in user', exclusions=['self', 'password'])
	async def login(self: 'Account', email: str, password: str, request: Request) -> LoginResponse :
		self._validateEmail(email)
		self._validatePassword(password)

		token_data = {
			'email': email,
			'ip': request.headers.get('cf-connecting-ip') or request.headers.get('x-forwarded-for') or request.client.host,
			'fp': browserFingerprint(request),
		}

		return await auth_client.login({
			'email': email,
			'password': password,
			'token_data': json_stream(token_data),
		})


	@HttpErrorHandler('creating user account')
	async def createAccount(self: 'Account', email: str, name: str) :
		self._validateEmail(email)
		data: TokenResponse = await auth_client.sign({
			'token_data': {
				'name': name,
				'email': email,
				'key': Account.AccountCreateKey,
			},
		})

		await sendEmail(
			f'{name} <{email}>',
			'Finish your fuzz.ly account',
			Account.VerifyEmailText,
			title=f'Hey, {name}',
			button=Button(text='Finalize Account', link=self._finalize_link.format(token=data.token)),
			subtext=Account.VerifyEmailSubtext,
		)


	@HttpErrorHandler('finalizing user account', exclusions=['self', 'password'])
	async def finalizeAccount(self: 'Account', name: str, handle: str, password: str, token: str, ip_address: str) -> LoginResponse :
		self._validatePassword(password)
		self._validateHandle(handle)

		try :
			token_data = await verifyToken(token, allow_non_user_tokens=True)

		except HttpError :
			raise BadRequest('the email confirmation key provided was invalid or could not be authenticated.')

		if token_data.data.get('key') != Account.AccountCreateKey :
			raise BadRequest('the token provided does not match the purpose required.')

		data: LoginResponse = await auth_client.create({
			'email': token_data.data['email'],
			'password': password,
			'name': name,
			'handle': handle,
			'token_data': {
				'email': token_data.data['email'],
				'ip': ip_address,
			},
		})

		await self.query_async(
			"""
			INSERT INTO kheina.public.tags
			(class_id, tag, owner)
			VALUES
			(tag_class_to_id(%s), %s, %s),
			(tag_class_to_id(%s), %s, %s),
			(tag_class_to_id(%s), %s, %s)
			""",
			(
				'artist', f'{handle.lower()}_(artist)', data['user_id'],
				'sponsor', f'{handle.lower()}_(sponsor)', data['user_id'],
				'subject', f'{handle.lower()}_(subject)', data['user_id'],
			),
			commit=True,
		)

		return data


	@HttpErrorHandler('changing user password', exclusions=['self', 'old_password', 'new_password'])
	async def changePassword(self: 'Account', email: str, old_password: str, new_password: str) -> None :
		self._validateEmail(email)
		self._validatePassword(old_password)
		self._validatePassword(new_password)

		await auth_client.change_password({
			'email': email,
			'old_password': old_password,
			'new_password': new_password,
		})


	@HttpErrorHandler('changing user handle', handlers = {
		UniqueViolation: (Conflict, 'A user already exists with the provided handle.'),
	})
	async def changeHandle(self: 'Account', user: KhUser, handle: str) :
		self._validateHandle(handle)
		await self.query_async("""
				UPDATE kheina.public.users
					SET handle = %s
				WHERE user_id = %s;
			""",
			(handle, user.user_id),
			commit=True,
		)


	@HttpErrorHandler('performing password recovery')
	async def recoverPassword(self: 'Account', email: str) :
		self._validateEmail(email)


		data: TokenResponse = await auth_client.sign({
			'token_data': {
				'email': email,
				'key': Account.AccountRecoveryKey,
			},
		})

		await sendEmail(
			f'User <{email}>',
			'Password recovery for your fuzz.ly account',
			Account.VerifyEmailText,
			title='Hey, fuzz.ly User',
			button=Button(text='Set New Password', link=self._recovery_link.format(token=data.token)),
			subtext='If you did not initiate this account recovery, you do not need to do anything. However, someone may be trying to gain access to your account. Changing your passwords may be a good idea.',
		)
