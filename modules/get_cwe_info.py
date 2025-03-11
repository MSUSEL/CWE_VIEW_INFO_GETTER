import json
import time
import requests
from requests import HTTPError, ConnectionError
from typing import Dict, List

def get_cwe_type_info_raw(cwe_id : str):
    '''
    :param cwe: this is the string id of the CWE in the form "1234"
    :return: string description of the CWE
    '''
    resp = requests.get("https://cwe-api.mitre.org/api/v1/cwe/" + cwe_id)
    resp.raise_for_status()
    resp.close()
    return resp.json()

def extract_type(resp):
    return resp[0]["Type"]

def get_type(ID : str) -> str:
    '''
    Queries the mitre CWE API
    :param ID: The ID of the CWE (any CWE) and just the numbers
    :return: The type of the CWE
    '''
    info = get_cwe_type_info_raw(ID)
    return extract_type(info)

def get_cwe_parents_raw(cwe_id : str, view_id : str):
    resp = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_id}/parents?view={view_id}")
    resp.raise_for_status()
    resp.close()
    return resp.json()

def get_cwe_children_raw(cwe_id : str, view_id : str):
    resp = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_id}/children?view={view_id}")
    resp.raise_for_status()
    resp.close()
    return resp.json()

def get_cwe_weakness_info_raw(id :str) -> Dict:
    resp = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}")
    resp.raise_for_status()
    resp.close()
    return resp.json()

def get_cwe_view_info_raw(id : str) -> Dict:
    resp = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/view/{id}")
    resp.raise_for_status()
    resp.close()
    return resp.json()

def extract_weakness(resp):
    if "Weaknesses" not in resp:
        print(resp)
        raise ValueError("Extract weaknesses failed")
    return resp["Weaknesses"][0]["Description"]

def get_weakness_description(info : Dict) -> str:
    '''
    :param info: json resp from the mitre CWE api /weakness/{id}
    :return: The description of the CWE
    :throws: ValueError if there is no description
    '''
    return extract_weakness(info)

def extract_view(resp):
    if "Views" not in resp:
        print(resp)
        raise ValueError("Extract views failed")
    return resp["Views"][0]["Objective"]

def get_view_description(info : Dict) -> str:
    '''
    :param info: json resp from the mitre CWE api /view/{id}
    :return: The objective of the view
    '''
    return extract_view(info)

def get_category_view_id(info : Dict) -> str:
    '''
    Queries the mitre CWE API
    :param ID: ID of the Category CWE (just numbers)
    :return: The description of the Category CWE
    '''
    try:
        if "Categories" not in info:
            raise ValueError(f"No key Categories")
        if info["Categories"][0]["Status"].lower() == "deprecated" or info["Categories"][0]["Status"].lower() == "obsolete":
            return None
        for rel in info["Categories"][0]["Relationships"]:
            if "Ordinal" not in rel:
                continue
            if "ViewID" not in rel:
                raise ValueError(f"No key ViewID")
            if rel["Ordinal"] == "Primary":
                return rel["ViewID"]
    except KeyError:
        id = info["Categories"][0]
        print(f"Key not found {id}")
        raise ValueError(f"No ViewID found for Category")

def get_weakness_view_id(info : Dict):
    '''
    Queries the mitre CWE API
    :param ID: ID of CWE that is not a category or a view.
    :return: The first view ID that the CWE belongs to.
    '''

    try:
        if "Weaknesses" not in info:
            raise KeyError(f"No key weaknesses")
        for weakness in info["Weaknesses"]:
            if weakness["ID"] in ["707", "284", "435", "664", "682", "691", "693", "697", "703", "707", "710"]:
                return "1000"
        if info["Weaknesses"][0]["Status"].lower() == "deprecated" or info["Weaknesses"][0]["Status"].lower() == "obsolete":
            return None
        for rel in info["Weaknesses"][0]["RelatedWeaknesses"]:
            if "Ordinal" not in rel:
                continue
            if "ViewID" not in rel:
                raise ValueError(f"No key ViewID")
            if rel["Ordinal"] == "Primary" and rel["Nature"] == "ChildOf":
                return rel["ViewID"]
    except KeyError as e:
        id = info["Weaknesses"][0]
        print(f"Key not found {id}")
        raise ValueError(f"No ViewID found")


def get_cwe_category_info_raw(id : str):
    resp = requests.get(f"https://cwe-api.mitre.org/api/v1/cwe/category/{id}")
    resp.raise_for_status()
    resp.close()
    return resp.json()

def extract_category(resp):
    if "Categories" not in resp:
        print(resp)
        raise ValueError("Extract Category failed")
    return resp["Categories"][0]["Summary"]

def get_category_description(info : Dict) -> str:
    '''
    Queries the mitre CWE API
    :param ID: Just the number id of the CWE you want the description for
    :return: description of the category
    '''
    return extract_category(info)

def extract_parent_ids(json_response : Dict) -> List[str]:
    '''
    Queries the mitre CWE API
    :param json_response: output of get_cwe_children_raw
    :return: list of parent CWEs just numbers
    '''
    list_of_parents_IDs = []
    for resp in json_response:
        list_of_parents_IDs.append(str(resp["ID"]))
    return list_of_parents_IDs

def extract_child_ids(json_response : Dict) -> List[str]:
    list_of_child_IDs = []
    for resp in json_response:
        list_of_child_IDs.append(str(resp["ID"]))
    return list_of_child_IDs

def get_parents(ID : str, view_id : str) -> List[str]:
    '''
    Queries the mitre CWE API
    :param ID: ID of the CWE just numbers in str form
    :param view_id: The view id of the CWE
    :return: list of parent CWEs just numbers
    '''
    response = get_cwe_parents_raw(ID, view_id )
    return extract_parent_ids(response)

def get_children(ID : str, view_id : str) -> List[str]:
    '''
    Queries the mitre CWE API
    :param ID: ID of the CWE just numbers in str form
    :param view_id: The view id of the CWE
    :return: list of child CWEs just numbers
    '''
    response = get_cwe_children_raw(ID, view_id )
    return extract_child_ids(response)
