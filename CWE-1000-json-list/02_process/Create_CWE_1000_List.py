import pandas as pd
import argparse
import json


def get_cwe_1000_id_list(csv_path : str):
    df = pd.read_csv(csv_path)
    list_of_cwe1000 = df.index.tolist()
    for i in range(0, len(list_of_cwe1000)):
        list_of_cwe1000[i] = "CWE-" + str(list_of_cwe1000[i])
    return list_of_cwe1000

def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='CWE-1000-json-list',
        description="create a list that has all CWE-1000 IDs"
    )
    parser.add_argument("-csv_path", type=str,dest="csv_path", help="path of the CVE-1000 csv")
    parser.add_argument("-o", type=str, dest="out_path", help="path of the CVE-1000 json")
    args = parser.parse_args()
    return args

def main():
    args = handle_args()
    csv_path = args.csv_path
    out_path = args.out_path
    CWE_1000_set = set(get_cwe_1000_id_list(csv_path))
    with open(out_path, "w") as out:
        json.dump(list(CWE_1000_set), out)

if __name__ == "__main__":
    main()