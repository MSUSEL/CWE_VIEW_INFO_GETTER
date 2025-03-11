import json
from modules.CWE_NODE import CWE_NODE
from typing import Dict

def jsonDump(dict_of_cwe_nodes : Dict[str, CWE_NODE], path) -> None:
    '''
    creates a json file of the str,CWE_NODE dictionary
    :param dict_of_cwe_nodes: this is the json representation of the map of cweNodes created by 1_cwe_anaylisis/02_process/cwe_relation_map.py
    :return: None
    '''
    dict_of_cwe_nodes_serializable : Dict[str, Dict] = {}
    for key, node in dict_of_cwe_nodes.items():
        dict_of_cwe_nodes_serializable[key] = dict_of_cwe_nodes[key].to_dict()

    with open(path, "w") as file:
        json.dump(dict_of_cwe_nodes_serializable, file)