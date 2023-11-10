import os
import joblib
import typing
import numpy as np
from mapping import VECTOR_MAAPPINGS
from exceptions import QueryParamsException, ModelExeception
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier


class SQLInjectionDetecor:
    vector_mappings: typing.Dict[str, str] = VECTOR_MAAPPINGS

    xgboost_model: XGBClassifier = joblib.load(
        os.path.join(os.getcwd(), "models/model__xgboost.joblib")
    )

    random_model: RandomForestClassifier = joblib.load(
        os.path.join(os.getcwd(), "models/model__random_forest.joblib")
    )

    def __init__(self, model: str):
        models = ["random", "xgb"]

        if model not in models:
            raise ModelExeception(f"model must be between this values {models}")

        self.model: typing.Union[XGBClassifier, RandomForestClassifier] = (
            self.random_model if model == "random" else self.xgboost_model
        )

    def detect_from_query_params(
        self, query_dict: typing.Union[dict, None] = None, url: str = None
    ):
        if not query_dict and not url:
            raise QueryParamsException("no query dictionary or url string found")

        results = []

        for field, value in query_dict.items():
            binary_mask = self.tokenize(value)

            if np.sum(binary_mask) == 0:
                results.append(
                    {"injection_dected": False, "field": field, "value": value}
                )

            else:
                prediction = self.model.predict(np.array(binary_mask).reshape(1, -1))

                if prediction[0] == 1:
                    results.append(
                        {"injection_dected": True, "field": field, "value": value}
                    )

                elif prediction[0] == 0:
                    results.append(
                        {"injection_dected": False, "field": field, "value": value}
                    )

        return results

    def detect_from_json_payload(self, json: typing.Union[dict, None]):
        for field in json:
            keywords = self.split_string(json[field])

            binary_mask = self.get_binary_array(keywords)

            if np.sum(binary_mask) == 0:
                return True

            print(self.model.predict(np.array(binary_mask).reshape(1, -1)))

        return None

    def split_string(self, query: str):
        # Split the SQL query into individual keywords

        return query.split()

    def get_binary_array(self, keywords: typing.List[str]):
        # Map each word to its corresponding vector (or to None if not found)

        mapped_vectors = [self.vector_mappings.get(word, None) for word in keywords]

        binary_array = [
            1 if VECTOR_MAAPPINGS.get(vector, None) in mapped_vectors else 0
            for vector in VECTOR_MAAPPINGS
        ]

        return binary_array

    def tokenize(self, value) -> typing.Union[typing.List, None]:
        keywords = self.split_string(value)

        binary_mask = self.get_binary_array(keywords)

        return binary_mask

    # def get_prediction(self, prediction):

    #     return True if prediction[0] == 1


if __name__ == "__main__":
    from pprint import pprint

    injector = SQLInjectionDetecor("random")

    pprint(
        injector.detect_from_query_params(
            query_dict={
                "user": "SELECT * FROM users WHERE username = 'wisdom'",
                # "password": "DELETE BULK mytable WHERE id = 2",
                "password": "DE",
            }
        )
    )
