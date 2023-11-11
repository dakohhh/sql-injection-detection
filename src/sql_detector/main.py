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

    xgboost_model: XGBClassifier = joblib.load(
        os.path.join(os.getcwd(), "sql_detector/models/model__xgboost.joblib")
    )

    random_model: RandomForestClassifier = joblib.load(
        os.path.join(os.getcwd(), "sql_detector/models/model__random_forest.joblib")
    )

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

    def get_binary_array(self, keywords: typing.List[str]):
        # Map each word to its corresponding vector (or to None if not found)

        mapped_vectors = [self.vector_mappings.get(word, None) for word in keywords]

        binary_array = [
            1 if self.vector_mappings.get(vector, None) in mapped_vectors else 0
            for vector in self.vector_mappings
        ]

        return binary_array

    def tokenize(self, value) -> typing.Union[typing.List, None]:
        keywords = self.split_string(value)

        binary_mask = self.get_binary_array(keywords)

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

    def detect(self, _dict: typing.Dict[str, str]):
        results = []

        for field, value in _dict.items():
            binary_mask = self.tokenize(value)

            if np.sum(binary_mask) == 0:
                results.append(
                    {"injection_detected": False, "field": field, "value": value}
                )

            else:
                prediction = self.model.predict(np.array(binary_mask).reshape(1, -1))

                if prediction[0] == 1:
                    results.append(
                        {"injection_detected": True, "field": field, "value": value}
                    )

                elif prediction[0] == 0:
                    results.append(
                        {"injection_detected": False, "field": field, "value": value}
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
