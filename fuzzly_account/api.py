from functools import wraps
from inspect import iscoroutinefunction
from typing import Any, Callable, Dict, Optional, Tuple

from aiohttp import ClientResponseError
from fuzzly_users.constants import Host
from fuzzly_users.internal import InternalUser
from fuzzly_users.models import User
from kh_common.gateway import Gateway


# this needs to be moved into kh_common
class Client :
	"""
	Defines a fuzz.ly client that can accept a bot token and self-manage authentication
	"""

	def __init__(self: 'Client', token: Optional[str] = None) :
		"""
		:param token: base64 encoded token generated from the fuzz.ly bot creation endpoint
		"""
		self._token: Optional[str] = token
		self._auth: Optional[str] = None


	async def start(self: 'Client') :
		# call account service to initialize auth
		pass


	def authenticated(self: 'Client', func: Gateway) -> Callable :
		if self._token and not self._auth :
			raise ValueError('authorization was not set! was Client.start called during init?')

		if not iscoroutinefunction(func) :
			raise NotImplementedError('provided func is not defined as async. did you pass in a kh_common.gateway.Gateway?')

		@wraps(func)
		async def wrapper(*args: Tuple[Any], **kwargs: Dict[str, Any]) -> Any :
			result: Any

			try :
				result = await func(*args, auth=self._auth, **kwargs)

			except ClientResponseError as e :
				if e.result != 401 or not self._token :
					raise

				# reauthorize
				await self.start()
				# now try re-running
				result = await func(*args, auth=self._auth, **kwargs)

			return result

		return wrapper


class UserClient(Client) :

	def __init__(self: 'UserClient', *a, **kv) :
		super().__init__(*a, **kv)
		self._user: Gateway = self.authenticated(Gateway(Host + '/i1/user/{user_id}', InternalUser, method='GET'))
		self.user: Gateway = self.authenticated(Gateway(Host + '/v1/user/{handle}', User, method='GET'))
