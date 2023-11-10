from fastapi import Request, status
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded



class UserExistException(Exception):
    def __init__(self, message: str):
        self.message = message   

async def user_exist_exception_handler(request: Request, exception: UserExistException):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "status": status.HTTP_409_CONFLICT, 
            "message": exception.message,
            "success": False,
        },
    )

class UnauthorizedException(Exception):
    def __init__(self, message: str):
        self.message = message   

async def unauthorized_exception_handler(request: Request, exception: UnauthorizedException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "status": status.HTTP_401_UNAUTHORIZED,
            "message": exception.message,
            "success": False
        },
    )



class ServerErrorException(Exception):
    def __init__(self, message: str):
        self.message = message   

async def server_exception_handler(request: Request, exception: ServerErrorException):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "message": exception.message,
            "success": False
        },
    )



class NotFoundException(Exception):
    def __init__(self, message:str):
        self.message = message

async def not_found(request: Request, exception: NotFoundException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "status": status.HTTP_404_NOT_FOUND,
            "message": exception.message,
            "success": False
        },
    )




class DatabaseException(Exception):
    def __init__(self, message: str):
        self.message = message

        
async def not_found_exception_handler(request: Request, exception: DatabaseException):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "message": exception.message,
            "success": False
        },
    )


class CredentialsException(Exception):
    def __init__(self, message: str):
        self.message = message



async def credentail_exception_handler(request: Request, exception: CredentialsException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "status": status.HTTP_401_UNAUTHORIZED,
            "message": exception.message,
            "success": False
        },
        headers={"WWW-Authenticate": "Bearer"}
    )




class BadRequestException(Exception):
    def __init__(self, message: str):
        self.message = message



async def bad_request_exception_handler(request: Request, exception: BadRequestException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "status": status.HTTP_400_BAD_REQUEST,
            "message": exception.message,
            "success": False
        },
    )



async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "status": status.HTTP_429_TOO_MANY_REQUESTS, 
            "message": str(exc.detail), 
            "success": False
        },
    )



