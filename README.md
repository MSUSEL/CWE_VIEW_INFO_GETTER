# CWE_VIEW_INFO_GETTER

the purpose of this tool is to fill out from you product factors to your diagnostics with the cwe view of your choice

the cwes in the product factors will be the cwes with out parents in the cwe view in other words the top level CWEs for the given view. all other connecting will need to be done by hand. 


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


# Must have pique def fram that looks like this 

This is an example feel free to change it ot meet your needs

```json
{
    "name": "WEB-qm-CWE-1000_trimmed_flat_measures",
    "additionalData": {},
    "global_config": {
        "benchmark_strategy": "calibration.WebBenchmarker",
        "normalizer": "pique.evaluation.DefaultNormalizer",
        "weights_strategy": "pique.calibration.NaiveWeighter"
    },
    "factors": {
        "tqi": {
            "Overall Quality": {
                "description": "The combined high-level score the software has received across the board."
            }
        },
        "quality_aspects": {
            "Security": {
                "description": "This is the highest level score for security for the software",
                "eval_strategy": "evaluation.QualityAspectEval",
                "children": {
                    "Product_Factor CWE-703": {},
                    "Product_Factor CWE-693": {},
                    "Product_Factor CWE-284": {},
                    "Product_Factor CWE-707": {},
                    "Product_Factor CWE-710": {},
                    "Product_Factor CWE-664": {},
                    "Product_Factor CWE-691": {},
                    "Product_Factor CWE-435": {},
                    "Product_Factor CWE-682": {},
                    "Product_Factor CWE-697": {},
                    "Product_Factor pf-other": {},
                    "Product_Factor pf-unknown": {}
                }
            }
        },
        "product_factors": {}
    },
    "measures":{},
    "diagnostics":{}
}

```

# Run

- Run the run.sh script

# Changing Behavior

- The add_other stage can be removed from the shell script if the pique model.

- The method of adding new insert behavior can be changed in the PiqueDefinitionFileAutoComplete.py script by adding a new strategy to the Abstract_Node_Adder.py.

# Conf 
 - All configuration can be done via the run.sh script simply change the arguments variables
 - You can even run it from here in PyCharm!!

```shell

#change the view ID to target a new view ***(changing from 1000 may cause errors)***
view_id=1000 #<<< change view target
number_of_threads=25
out_put=./Get_CWE_Relation_Info/04_product/full_CWE_$view_id.json # <<< change output location
pique_def=/home/aidan/LAB/Web-PIQUE-model/src/main/resources/Web-security-extensible-model-CWE-1000-Flat-Measures_prop_wieghter.json #insert location of file to adjust
cwe_list=./Add_Other_Node/04_product/CWE-$view_id-_w_other_unknown.json

url=https://cwe.mitre.org/data/csv/$view_id.csv.zip



python3 ./CWE-1000-csv-get/02_process/get_cwe_1000_csv.py -url $url -dest ./CWE-1000-csv-get/04_product
python3 ./CWE-1000-json-list/02_process/Create_CWE_1000_List.py -o ./CWE-1000-json-list/04_product/CWE-$view_id.json -csv_path ./CWE-1000-csv-get/04_product/$view_id.csv
python3 ./Get_CWE_1000_info/02_process/CWE_1000_Info_Gather.py -o ./Get_CWE_1000_info/04_product/CWE_$view_id-info.json -json_path ./CWE-1000-json-list/04_product/CWE-$view_id.json -n $number_of_threads
python3 ./Get_CWE_Relation_Info/02_process/Get_Rel_info.py -o $out_put -json_path ./Get_CWE_1000_info/04_product/CWE_$view_id-info.json -n $number_of_threads
python3 ./Add_Other_Node/02_process/add_other.py -in Get_CWE_Relation_Info/04_product/full_CWE_$view_id.json -out Add_Other_Node/04_product/CWE-$view_id-_w_other_unknown.json
python3 ./PiqueDefinitionFileCreator/02_process/PiqueDefinitionFileAutoComplete.py -pd $pique_def -cwe $cwe_list
```
