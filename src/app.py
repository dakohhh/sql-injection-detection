import typing
from fastapi import FastAPI, Request
from response.response import CustomResponse
from sql_detector import SQLInjectionDetecor



app = FastAPI()




injection_detector = SQLInjectionDetecor("xgb")




@app.get("/detect/json")
def detect_injection_from_json(request:Request, payload: typing.Dict):

    results = injection_detector.detect_from_json_payload(payload)

    return CustomResponse("injection results", data=results)








