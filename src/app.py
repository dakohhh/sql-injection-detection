import typing
from fastapi import FastAPI, Request
from pydantic import BaseModel
from response.response import CustomResponse
from sql_detector import SQLInjectionDetecor



app = FastAPI(title="SQL Injection Detection API")



class PayloadBody(BaseModel):

    data: typing.Dict[str, str]


    
class QueryBody(BaseModel):

    url: typing.Optional[str]

    json_: typing.Optional[typing.Dict[str, str]]



injection_detector = SQLInjectionDetecor("random")




@app.post("/detect/json")
def detect_injection_from_json(request:Request, payload: PayloadBody):

    results = injection_detector.detect_from_json_payload(payload.data)

    return CustomResponse("injection results", data=results)




@app.post("/detect/query_params")
def detect_injection_from_query(request:Request, query: QueryBody):


    results = injection_detector.detect_from_query_params(query.json_, url=query.url)


    return CustomResponse("injection results", data=results)








