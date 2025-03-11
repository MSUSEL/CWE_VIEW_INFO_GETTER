import requests
import zipfile
import io
from requests import HTTPError
import argparse



def get_cwe_1000_csv(url : str, dest : str):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip:

            zip.extractall(dest)

    except IOError as IO_err:
        print(IO_err)

    except HTTPError as HTTP_err:
        print(HTTP_err)
        print(f"Error getting csv: {url}")

def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='get_cwe_1000_csv',
        description="Get the csv tht contains the CWE-1000 view info"
    )
    parser.add_argument("-url", type=str,dest="url", help="url of the CVE-1000 csv")
    parser.add_argument("-dest", type=str,dest="dest", help="Location of CWE-1000 csv")
    args = parser.parse_args()
    return args

def main():
    args : argparse.Namespace = handle_args()
    dest = args.dest
    url = args.url
    get_cwe_1000_csv(url, dest)

if __name__ == "__main__":
    main()