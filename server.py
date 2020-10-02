from models import InheritRequest, PostRequest, TagsRequest, UpdateRequest
from kh_common.auth import authenticated, TokenData
from kh_common.exceptions import jsonErrorHandler
from kh_common.validation import validatedJson
from starlette.responses import UJSONResponse
from kh_common.logging import getLogger
from traceback import format_tb
import time


logger = getLogger()
# tagger = Tagger()


# @jsonErrorHandler
# @authenticated
# @validatedJson
# async def v1AddTags(req: TagsRequest, token:TokenData=None) :
# 	"""
# 	{
# 		"post_id": str,
# 		"tags": [
# 			str
# 		]
# 	}
# 	"""

# 	return UJSONResponse(
# 		tagger.addTags(
# 			token.data['user_id'],
# 			req.post_id,
# 			tuple(req.tags),
# 		)
# 	)


# @jsonErrorHandler
# @authenticated
# @validatedJson
# async def v1RemoveTags(req: TagsRequest, token:TokenData=None) :
# 	"""
# 	{
# 		"post_id": str,
# 		"tags": [
# 			str
# 		]
# 	}
# 	"""

# 	return UJSONResponse(
# 		tagger.removeTags(
# 			token.data['user_id'],
# 			req.post_id,
# 			tuple(req.tags),
# 		)
# 	)


# @jsonErrorHandler
# @authenticated
# @validatedJson
# async def v1InheritTag(req: InheritRequest, token:TokenData=None) :
# 	"""
# 	{
# 		"parent_tag": str,
# 		"child_tag": str,
# 		"deprecate": Optional[bool],
# 		"admin": Optional[bool]
# 	}
# 	"""

# 	return UJSONResponse(
# 		tagger.inheritTag(
# 			token.data['user_id'],
# 			req.parent_tag,
# 			req.child_tag,
# 			req.deprecate,
# 			token.data.get('admin'),
# 		)
# 	)


# @jsonErrorHandler
# @authenticated
# @validatedJson
# async def v1UpdateTag(req: UpdateRequest, token:TokenData=None) :
# 	"""
# 	{
# 		"tag": str,
# 		"tag_class": Optional[str],
# 		"owner": Optional[str],
# 		"admin": Optional[bool]
# 	}
# 	"""

# 	return UJSONResponse(
# 		tagger.updateTag(
# 			token.data['user_id'],
# 			UpdateRequest.tag,
# 			UpdateRequest.tag_class,
# 			UpdateRequest.owner,
# 			token.data.get('admin'),
# 		)
# 	)


# @jsonErrorHandler
# @authenticated
# @validatedJson
# async def v1FetchTags(req: PostRequest, token:TokenData=None) :
# 	"""
# 	{
# 		"post_id": str
# 	}
# 	"""

# 	return UJSONResponse(
# 		tagger.fetchTagsByPost(
# 			token.data['user_id'],
# 			req.post_id,
# 		)
# 	)


# async def v1Help(req) :
# 	return UJSONResponse({
# 		'/v1/create_post': {
# 			'auth': {
# 				'required': True,
# 				'user_id': 'int',
# 			},
# 		},
# 		'/v1/upload_image': {
# 			'auth': {
# 				'required': True,
# 				'user_id': 'int',
# 			},
# 			'file': 'image',
# 			'post_id': 'Optional[str]',
# 		},
# 		'/v1/update_post': {
# 			'auth': {
# 				'required': True,
# 				'user_id': 'int',
# 			},
# 			'privacy': 'Optional[str]',
# 			'title': 'Optional[str]',
# 			'description': 'Optional[str]',
# 		},
# 	})


# async def shutdown() :
# 	uploader.close()


@jsonErrorHandler
async def test(req: Request) :
	print(req.path_params)


from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Route, Mount

middleware = [
	Middleware(TrustedHostMiddleware, allowed_hosts={ 'localhost', '127.0.0.1', 'account.kheina.com', 'account-dev.kheina.com' }),
]

routes = [
	# Route('/v1/add_tags', endpoint=v1AddTags, methods=('POST',)),
	# Route('/v1/remove_tags', endpoint=v1RemoveTags, methods=('POST',)),
	# Route('/v1/inherit_tag', endpoint=v1InheritTag, methods=('POST',)),
	# Route('/v1/update_tag', endpoint=v1UpdateTag, methods=('POST',)),
	# Route('/v1/fetch_tags', endpoint=v1FetchTags, methods=('POST',)),
	# Route('/v1/help', endpoint=v1Help, methods=('GET',)),
	Route('/test/{biscuit}', endpoint=v1Help, methods=('GET',)),
]

app = Starlette(
	routes=routes,
	middleware=middleware,
	on_shutdown=[shutdown],
)

if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=5003)
