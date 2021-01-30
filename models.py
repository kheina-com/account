from typing import List, Optional
from pydantic import BaseModel


class LoginRequest(BaseModel) :
	email: str
	password: str


class CreateAccountRequest(BaseModel) :
	email: str
	name: str


class FinalizeAccountRequest(LoginRequest, CreateAccountRequest) :
	handle: str
	token: str


class ChangePasswordRequest(LoginRequest) :
	new_password: str
