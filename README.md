# CWE_VIEW_INFO_GETTER

## This is a tool for gathering information about CVE-1000 

### Output

```json
{
  "287": {
    "name": "CWE-287", 
    "children": ["1390", "295", "306", "645"], 
    "parents": ["284"], 
    "description": "When an actor claims to have a ...", 
    "type": "class_weakness", 
    "view_id": "1000"}
}
```
- To get info on children and parents use the child ID as a key in the Dictionary


# Run

- Run the run.sh script

# Conf 
 - All configuration can be done via the run.sh script simply change the arguments variables
 - You can even run it from here in PyCharm!!

```shell

#change the view ID to target a new view ***(changing from 1000 may cause errors)***
view_id=1000 #<<< change view target


url=https://cwe.mitre.org/data/csv/$view_id.csv.zip



python3 ./CWE-1000-csv-get/02_process/get_cwe_1000_csv.py -url $url -dest ./CWE-1000-csv-get/04_product
python3 ./CWE-1000-json-list/02_process/Create_CWE_1000_List.py -o ./CWE-1000-json-list/04_product/CWE-$view_id.json -csv_path ./CWE-1000-csv-get/04_product/$view_id.csv
python3 ./Get_CWE_1000_info/02_process/CWE_1000_Info_Gather.py -o ./Get_CWE_1000_info/04_product/CWE_$view_id-info.json -json_path ./CWE-1000-json-list/04_product/CWE-$view_id.json
python3 ./Get_CWE_Relation_Info/02_process/Get_Rel_info.py -o ./Get_CWE_Relation_Info/04_product/full_CWE_$view_id.json -json_path ./Get_CWE_1000_info/04_product/CWE_$view_id-info.json
```
