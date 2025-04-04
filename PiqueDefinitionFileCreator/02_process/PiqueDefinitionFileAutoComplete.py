import json
import sys
import os
import argparse

from typing import Dict
from modules.CWE_NODE import CWE_NODE
from modules.reloadDict import reload_dict
from Abstract_Node_Adder import AddNodesToPiqueDefinition, MeasureAdderFlat, ProductFactorAdderFlat, DiagnosticAdder



def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='PiqueDefinitionFileAutoComplete',
        description="Provide JSON of CWEs that you would wish to have included in you pique security file"
    )
    parser.add_argument("-pd", type=str,dest="pique_def", help="Location of Pique definition file")
    parser.add_argument("-cwe", type=str,dest="cwe", help="Json file of CWEs in the form k = str v = CWE_NODE.to_dict()")
    args = parser.parse_args()
    return args

def main():
    args = handle_args()
    pique_definition_file = args.pique_def
    json_file = args.cwe
    with open(json_file, "r") as json_file:
        json_data = json.load(json_file)
        CWEs : Dict[str, CWE_NODE] = reload_dict(json_data)
    with open(pique_definition_file, "r") as json_file:
        pique_definition = json.load(json_file)

    diagnostic_adder = DiagnosticAdder()
    measure_adder = MeasureAdderFlat()
    product_factor_adder = ProductFactorAdderFlat(CWEs)


    add_node = AddNodesToPiqueDefinition(pique_definition)

    pf_nodes = [node for node in CWEs.values() if len(node.parents) == 0 ]
    add_node.add_nodes_to_pique_definition(pf_nodes, product_factor_adder)

    measure_nodes = [node for node in CWEs.values() if len(node.parents) != 0 ]
    add_node.add_nodes_to_pique_definition(measure_nodes, measure_adder)

    diagnostic_nodes = [node for node in CWEs.values() if len(node.parents) != 0 ]
    add_node.add_nodes_to_pique_definition(diagnostic_nodes, diagnostic_adder)

    with open(pique_definition_file, "w") as json_file:
        json.dump(pique_definition, json_file, indent=4)


if __name__ == '__main__':
    main()