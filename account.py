from kh_common.exceptions.http_error import BadRequest, Forbidden, HttpError, HttpErrorHandler, NotFound, InternalServerError
from kh_common.config.constants import auth_host, environment, Environment
from aiohttp import ClientTimeout, request as async_request
from kh_common.caching import ArgsCache, SimpleCache
from kh_common.config.constants import auth_host
from re import IGNORECASE, compile as re_compile
from kh_common.utilities.json import json_stream
from typing import Dict, List, Optional, Tuple
from kh_common.email import Button, sendEmail
from kh_common.auth import verifyToken, Scope
from psycopg2.errors import UniqueViolation
from kh_common.logging import getLogger
from kh_common.hashing import Hashable
from uuid import uuid4
import json


class Account(Hashable) :

	EmailRegex = re_compile(r'^(?P<user>[A-Z0-9._%+-]+)@(?P<domain>[A-Z0-9.-]+\.[A-Z]{2,})$', flags=IGNORECASE)
	VerifyEmailText = "Finish creating your new account at kheina.com by clicking the button below. If you didn't make this request, you can safely ignore this email."
	VerifyEmailSubtext = 'kheina.com does not store your private information, including your email. You will not receive another email without directly requesting it.'


	def __init__(self) :
		Hashable.__init__(self)
		self._auth_timeout = 30

		if environment == Environment.prod :
			self._finalize_link = 'https://kheina.com/account/finalize?token={token}'
		else :
			self._finalize_link = 'https://dev.kheina.com/account/finalize?token={token}'


	def _validateEmail(self, email: str) :
		email = Account.EmailRegex.search(email)
		if not email :
			raise BadRequest('the given email is invalid.')
		return email.groupdict()


	def _validatePassword(self, password: str) :
		if len(password) < 10 :
			raise BadRequest('the given password is invalid. passwords need to be at least 10 characters.')


	@HttpErrorHandler('logging in user')
	async def login(self, email: str, password: str, ip_address: str) :
		admin = self._validateEmail(email)['domain'] == 'kheina.com'
		self._validatePassword(password)

		token_data = {
			'email': email,
			'ip': ip_address,
		}

		if admin :
			token_data['scope'] = Scope.admin.all_included_scopes()

		async with async_request(
			'POST',
			f'{auth_host}/v1/login',
			json={
				'email': email,
				'password': password,
				'generate_token': True,
				'token_data': json_stream(token_data),
			},
			timeout=ClientTimeout(self._auth_timeout),
		) as response :
			return await response.json()


	@HttpErrorHandler('creating user account')
	async def createAccount(self, email: str, name: str) :
		self._validateEmail(email)

		async with async_request(
			'POST',
			f'{auth_host}/v1/sign_data',
			json={
				'token_data': {
					'name': name,
					'email': email,
					'purpose': 'create account',
				},
			},
			timeout=ClientTimeout(self._auth_timeout),
		) as response :
			data = await response.json()

		await sendEmail(
			f'{name} <{email}>',
			'Finish your kheina.com account',
			Account.VerifyEmailText,
			title=f'Hey, {name}',
			button=Button(text='Finalize Account', link=self._finalize_link.format(token=data['token'])),
			subtext=Account.VerifyEmailSubtext,
		)


	@HttpErrorHandler('finalizing user account')
	async def finalizeAccount(self, name: str, handle: str, email: str, password: str, token:str=None) :
		self._validateEmail(email)
		self._validatePassword(password)

		try :
			token_data = verifyToken(token)
		except HttpError :
			raise BadRequest('the email confirmation key provided was invalid or could not be authenticated.')

		if token_data.data['email'] != email :
			raise BadRequest('the email provided in the request was not the same email as provided.')

		if token_data.data['purpose'] != 'create account' :
			raise BadRequest('the token provided does not match the purpose required.')

		async with async_request(
			'POST',
			f'{auth_host}/v1/create',
			json={
				'email': email,
				'password': password,
				'name': name,
				'handle': handle,
			},
			timeout=ClientTimeout(self._auth_timeout),
		) as response :
			data = await response.json()
			return data


	@HttpErrorHandler('changing user password')
	async def changePassword(self, email: str, old_password: str, new_password: str) :
		self._validateEmail(email)
		self._validatePassword(old_password)
		self._validatePassword(new_password)

		async with async_request(
			'POST',
			f'{auth_host}/v1/change_password',
			json={
				'email': email,
				'old_password': old_password,
				'new_password': new_password,
			},
			timeout=ClientTimeout(self._auth_timeout),
		) as response :
			data = await response.json()
			return data
