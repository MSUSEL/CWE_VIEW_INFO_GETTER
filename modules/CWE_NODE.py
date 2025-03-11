from typing import Dict

class CWE_NODE:

    def __init__(self, name: str = ""):
        self.name : str = name
        self.children : list[str] = []
        self.parents : list[str] = []
        self.description : str = ""
        self.type : str = ""
        self.view_id : str = ""


    def reload (self, dict : Dict[str, str]):
        if type(dict) == str:
            print(dict)
            exit(0)
        self.name = dict["name"]
        self.children = dict["children"]
        self.parents = dict["parents"]
        self.description = dict["description"]
        self.type = dict["type"]
        self.view_id = dict["view_id"]
        return self

    def to_dict(self):
        return {
            "name": self.name,
            "children": self.children,
            "parents": self.parents,
            "description": self.description,
            "type": self.type,
            "view_id": self.view_id
        }


