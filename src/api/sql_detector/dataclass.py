from dataclasses import dataclass



@dataclass
class SQLInjectionResult():

    field:str

    value: int

    injection_dected: bool








print(SQLInjectionResult("we", 2, True).__dict__)