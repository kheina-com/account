from kh_common.exceptions.http_error import BadRequest, Forbidden, NotFound, InternalServerError
from aiohttp import ClientTimeout, request as async_request
from kh_common.caching import ArgsCache, SimpleCache
from re import IGNORECASE, compile as re_compile
from kh_common.config.constants import auth_host
from typing import Dict, List, Optional, Tuple
from psycopg2.errors import UniqueViolation
from kh_common.logging import getLogger
from kh_common.hashing import Hashable
from uuid import uuid4
import json


class Account(Hashable) :

	EmailRegex = re_compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', flags=IGNORECASE)


	def __init__(self) :
		Hashable.__init__(self)
		self._auth_timeout = 30


	def _validateEmail(self, email: str) :
		if not Account.EmailRegex.search(email) :
			raise BadRequest('the given email is invalid.')


	def _validatePassword(self, password: str) :
		if len(password) < 10 :
			raise BadRequest('the given password is invalid. passwords need to be at least 10 characters.')


	async def login(self, email: str, password: str, ip_address: str) :
		self._validateEmail(email)
		# self._validatePassword(password)

		async with async_request(
			'POST',
			f'{auth_host}/v1/login',
			json={
				'email': email,
				'password': password,
				'generate_token': True,
				'token_data': {
					'email': email,
					'ip': ip_address,
				},
			},
			timeout=ClientTimeout(self._auth_timeout),
		) as response :
			data = json.loads(await response.text())
			return data


	async def createAccount(self, name: str, handle: str, email: str, password: str) :
		self._validateEmail(email)
		self._validatePassword(password)

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
			data = json.loads(await response.text())
			return data


	async def changePassword(self, email: str, old_password: str, new_password: str) :
		self._validateEmail(email)
		# self._validatePassword(old_password)
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
			data = json.loads(await response.text())
			return data
