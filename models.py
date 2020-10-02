from typing import List, Optional
from pydantic import BaseModel


class PostRequest(BaseModel) :
	post_id: str


class TagsRequest(PostRequest) :
	tags: List[str]


class InheritRequest(BaseModel) :
	parent_tag: str
	child_tag: str
	deprecate: Optional[bool]
	admin: Optional[bool]


class UpdateRequest(BaseModel) :
	tag: str
	tag_class: Optional[str]
	owner: Optional[str]
	admin: Optional[bool]
