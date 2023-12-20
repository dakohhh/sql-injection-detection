import os
import json
import joblib
import typing
import numpy as np
from . import mapping
from . import exceptions
from urllib.parse import urlparse, parse_qs
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier


class SQLInjectionDetecor:
    vector_mappings: typing.Dict[str, str] = mapping.VECTOR_MAAPPINGS

    xgboost_model: XGBClassifier = None

    with open("./sql_injector_detector/models/model__xgboost.joblib", "rb") as __model:
        xgboost_model: XGBClassifier = joblib.load(__model)

    random_model: RandomForestClassifier = None

    with open("./sql_injector_detector/models/model__random_forest.joblib", "rb") as __model:
        random_model: RandomForestClassifier = joblib.load(__model)

    def __init__(self, model: str):
        models = ["random", "xgb"]

        if model not in models:
            raise exceptions.ModelExeception(
                f"model must be between this values {models}"
            )

        self.model: typing.Union[XGBClassifier, RandomForestClassifier] = (
            self.random_model if model == "random" else self.xgboost_model
        )

    def detect_from_query_params(
        self, query_dict: typing.Dict[str, str] = None, url: str = None
    ):
        if not query_dict and not (url and url.strip()):
            raise exceptions.QueryParamsException(
                "no query dictionary or url string found"
            )

        if url and query_dict:
            query_dict_url = self.parse_url(url)

            results = self.detect(query_dict_url) + self.detect(query_dict)
            return results

        else:
            results = self.detect(query_dict)

            return results

    def detect_from_json_payload(
        self, payload: typing.Union[typing.Dict[str, typing.Any], str]
    ):
        if isinstance(payload, str):
            return self.detect(json.loads(payload))

        elif isinstance(payload, dict):
            return self.detect(payload)

        else:
            raise Exception(
                "The json payload must be a valid str or dict or JSON like object"
            )

    def split_string(self, query: str):
        # Split the SQL query into individual keywords, if query is not string then return the split string representation

        return str(query).split()

    def get_binary_array(self, mapped_vectors: typing.List[str]):
        # Map each word to its corresponding vector (or to None if not found)

        binary_array = [
            1 if self.vector_mappings.get(vector, None) in mapped_vectors else 0
            for vector in self.vector_mappings
        ]

        return binary_array

    def tokenize(self, mask:typing.List[str]) -> typing.Union[typing.List, None]:

        binary_mask = self.get_binary_array(mask)

        return binary_mask

    def parse_url(self, url: str) -> typing.Dict[str, str]:
        if not isinstance(url, str):
            raise Exception("URL passed must be a valid str object")

        parsed_url = urlparse(url)

        query_params = (
            parse_qs(parsed_url.path)
            if parsed_url.query == "" and parsed_url.scheme == ""
            else parse_qs(parsed_url.query)
        )

        result = {key: value[0] for key, value in query_params.items()}

        if result == {}:
            raise Exception("Did not find query params in url")

        return result
    

    def map_mask(self, string_value:str):
        mask = []

        for k, v in self.vector_mappings.items():

            if k.lower() in string_value.lower():

                mask.append(v)

        return mask

    def detect(self, _dict: typing.Dict[str, str]):
        results = []


        for field, string_value in _dict.items():
            
            mask = self.map_mask(string_value)

            binary_mask = self.tokenize(mask)


            if np.sum(binary_mask) == 0:
                results.append(
                    {"injection_detected": False, "field": field, "value": string_value}
                )

            else:
                prediction = self.model.predict(np.array(binary_mask).reshape(1, -1))

                if prediction[0] == 1:
                    results.append(
                        {"injection_detected": True, "field": field, "value": string_value}
                    )

                elif prediction[0] == 0:
                    results.append(
                        {"injection_detected": False, "field": field, "value": string_value}
                    )

        return results


if __name__ == "__main__":
    from pprint import pprint

    injector = SQLInjectionDetecor("xgb")

    pprint(
        injector.detect_from_json_payload(
            payload={
                "user": "SELECT * FROM users WHERE username = 'wisdom'",
                "password": 3,
                "per": "8f9e4e6e-169b-46f0-b55c-0d15a9d304ae",
            }
        )
    )

    # pprint(injector.parse_url(url="https://chat.openai.com/c/8f9e4e6e-169b-46f0-b55c-0d15a9d304ae"))
