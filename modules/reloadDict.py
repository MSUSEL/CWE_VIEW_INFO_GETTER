from typing import Dict
from modules.CWE_NODE import CWE_NODE

def reload_dict(dict : Dict[str, Dict]) -> Dict[str, CWE_NODE]:
    '''
    recreate a map of CWE id to CWE_NODE objects from a json file
    :param dict: The result from using the jsonDump function found in this module on a Dict[str,CWE_NODE] object.
    :return: The Dict[str,CWE_NODE] object from the input json file
    '''

    new_dict = {}
    for key, value in dict.items():
        new_dict[key] = CWE_NODE().reload(value)
    return new_dict
