from typing import List, Optional
from pydantic import BaseModel


class LoginRequest(BaseModel) :
	email: str
	password: str


class CreateAccountRequest(LoginRequest) :
	name: str
	handle: str


class ChangePasswordRequest(LoginRequest) :
	new_password: str
