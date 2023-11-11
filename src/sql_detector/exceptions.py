import typing





class  SQLInjectionException(Exception):

    '''Base exception class for SQL Injection Detector'''

    def __init__(self, message):

        super().__init__(message)




class ModelExeception(SQLInjectionException):...


class  QueryParamsException(SQLInjectionException):

    def __init__(self, message):

        super().__init__(message)



    