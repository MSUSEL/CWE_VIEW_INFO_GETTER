import argparse
from modules.get_cwe_info import *
from modules.CWE_NODE import CWE_NODE
from modules.progress_bar import print_progress_bar
from modules.json_dump import jsonDump
from typing import Dict, List
import json
from concurrent.futures import ThreadPoolExecutor




def cwe_info_gather( list_of_cwes_in_nvd : List[str], out_path : str, thread_count : int) -> None:
    '''
    creates a json file that is that maps cwe-id to CWE_NODE structure filled with all fields but parents and children
    :param list_of_cwes_in_nvd: List of CWEs to get info for
    :param out_path: output path for cwe_info_gather()
    :param thread_count: number of threads in use at one time
    :return: None
    '''
    #data structures
    dict_of_cwe_nodes : Dict[str, CWE_NODE] = {}
    count = len(list_of_cwes_in_nvd)
    i = 0
    try:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            results = executor.map(get_cwe_info, list_of_cwes_in_nvd)
            for result in results:
                dict_of_cwe_nodes[result[1]] = result[0]
                print_progress_bar(i, count)
                i+=1
    except HTTPError as http_err:
        jsonDump(dict_of_cwe_nodes, out_path)
        print(http_err)
        exit(1)
    except ValueError as err:
        jsonDump(dict_of_cwe_nodes, out_path)
        print(err)
        exit(1)

    jsonDump(dict_of_cwe_nodes, out_path)


def get_cwe_info(cwe):
    id_of_cwe = cwe.strip("CWE-")
    type_of_cwe = get_type(id_of_cwe)
    if type_of_cwe.lower() == "category" or type_of_cwe.lower() == "deprecated_category":
        category_info = get_cwe_category_info_raw(id_of_cwe)
        description = get_category_description(category_info)
        view_id = get_category_view_id(category_info)
    elif type_of_cwe.lower() == "view":
        view_info = get_cwe_view_info_raw(id_of_cwe)
        description = get_view_description(view_info)
        view_id = id_of_cwe
    else:
        weakness_info = get_cwe_weakness_info_raw(id_of_cwe)
        description = get_weakness_description(weakness_info)
        view_id = get_weakness_view_id(weakness_info)
    cwe_node = CWE_NODE(cwe)
    cwe_node.type = type_of_cwe
    cwe_node.view_id = view_id
    cwe_node.description = description
    return [cwe_node, id_of_cwe]


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
    threads_count = int(args.n_threads)
    with open(json_path) as f:
        list_of_cwes_in_nvd = list(json.load(f))

    cwe_info_gather(list_of_cwes_in_nvd, out_path, threads_count)

if __name__ == "__main__":
    __main__()