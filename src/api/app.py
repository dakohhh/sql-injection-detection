from fastapi import FastAPI, Form
from sql_detector import SQLInjectionDetecor
import os
import certifi
from fastapi import FastAPI, Request



app = FastAPI()






@app.get("/tests")
def tests(request:Request, rat:str, user=Form()):

    

    print(rat)

    return None








