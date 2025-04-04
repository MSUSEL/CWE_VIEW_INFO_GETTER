import argparse
import json
import sys

from modules.CWE_NODE import CWE_NODE
from modules.reloadDict import reload_dict
from modules.json_dump import jsonDump


def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='add_other',
        description="add other and unknown to you security hierarchy."
    )
    parser.add_argument("-in", type=str,dest="in_path", help="location of full cwe json file")
    parser.add_argument("-out", type=str,dest="out_path", help="location of file with cwe-other and unknown added")
    args = parser.parse_args()
    return args

def main():

    args = handle_args()

    with open(args.in_path, "r") as pique_definition_file:
        data = json.load(pique_definition_file)
        CWEs = reload_dict(data)

    pf_other = CWE_NODE()
    pf_other.parents =[]
    pf_other.children = ["other"]
    pf_other.name = "pf-other"
    pf_other.type = "other"
    pf_other.description = "Catch for CWEs that do not fit in the CWE-1000 view"

    m_other = CWE_NODE()
    m_other.parents =["pf-other"]
    m_other.children = []
    m_other.name = "CWE-other"
    m_other.type = "other"
    m_other.description = "Catch for CWEs that do not fit in the CWE-1000 view"

    pf_unknown = CWE_NODE()
    pf_unknown.parents =[]
    pf_unknown.children = ["unknown"]
    pf_unknown.name = "pf-unknown"
    pf_unknown.type = "unknown"
    pf_unknown.description = "Catch for CVEs that do not map to a CWE"

    m_unknown = CWE_NODE()
    m_unknown.parents =["pf-unknown"]
    m_unknown.children = []
    m_unknown.name = "CWE-unknown"
    m_unknown.type = "unknown"
    m_unknown.description = "Catch for CVEs that do not map to a CWE"

    CWEs["pf-other"] =pf_other
    CWEs["pf-unknown"] = pf_unknown
    CWEs["other"] = m_other
    CWEs["unknown"] = m_unknown

    jsonDump(CWEs, args.out_path)

if __name__ == "__main__":
    main()


