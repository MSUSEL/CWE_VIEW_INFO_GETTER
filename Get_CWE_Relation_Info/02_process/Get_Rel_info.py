import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
import json
from requests.exceptions import HTTPError
from modules.json_dump import jsonDump
from modules.progress_bar import print_progress_bar
from modules.CWE_NODE import CWE_NODE
from modules.get_cwe_info import get_parents, get_children
from typing import Dict


def assign_cwe_relationships(dict_of_cwes : Dict, out_path : str, thread_count : int) -> None:

    dict_out = {}

    count = len(dict_of_cwes)
    i = 0

    print_progress_bar(i, count)


    try:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            for result in executor.map(lambda p: get_relation_info(*p), dict_of_cwes.items()):
                dict_out[result[0]] = result[1]
                i += 1
                print_progress_bar(i, count)
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        jsonDump(dict_out, out_path)
        exit(1)
    except ValueError as err:
        print(f"ValueError occurred: {err}")
        jsonDump(dict_out, out_path)
        exit(1)
    except Exception as err:
        print(f"Unknown error occurred: {err}")
        jsonDump(dict_out, out_path)
        exit(1)


    jsonDump(dict_out, out_path)


def get_relation_info(key, value):
    cwe_node = CWE_NODE().reload(value)
    type_of_cwe = cwe_node.type
    if type_of_cwe.lower() == "category" or type_of_cwe.lower() == "deprecated_category":
        cwe_node.children = get_children(key, cwe_node.view_id)
        cwe_node.parents = get_parents(key, cwe_node.view_id)
    elif type_of_cwe.lower() == "view":
        cwe_node.children = get_children(key, cwe_node.view_id)
        cwe_node.parents = get_parents(key, cwe_node.view_id)
    else:
        cwe_node.children = get_children(key, cwe_node.view_id)
        cwe_node.parents = get_parents(key, cwe_node.view_id)
    return [key, cwe_node]


def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='CWE-1000-json-list',
        description="create a list that has all CWE-1000 IDs"
    )
    parser.add_argument("-json_path", type=str,dest="json_path", help="path of the CVE-1000 json")
    parser.add_argument("-o", type=str, dest="out_path", help="path of the CVE-1000 json")
    parser.add_argument("-n", type=str, dest="n_threads", help="number of threads you would like to run")
    args = parser.parse_args()
    return args

def __main__():
    args = handle_args()
    out_path = args.out_path
    json_path = args.json_path
    n_threads = args.n_threads
    with open(json_path, 'r') as f:
        dict_of_cwes = json.load(f)
    assign_cwe_relationships(dict_of_cwes, out_path, n_threads)

if __name__ == "__main__":
    __main__()