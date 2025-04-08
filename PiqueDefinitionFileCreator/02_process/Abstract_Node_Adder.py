from abc import ABC, abstractmethod
from typing import List, Tuple, Dict
from modules.CWE_NODE import CWE_NODE

class AddingStrategy(ABC):
    @abstractmethod
    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        pass


class ProductFactorAdderFlat(AddingStrategy):
    def __init__(self, CWEs : Dict[str,CWE_NODE]):
        self.CWEs = CWEs

    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        if "factors" not in pique_definition_file_location:
            raise KeyError(f"Pique Definition File has no factors section")
        if "product_factors" not in pique_definition_file_location["factors"]:
            raise KeyError(f"Pique Definition File has no product_factors section")
        children = {}
        child_ids = []
        self.get_child_ids(node, self.CWEs, child_ids)
        for child_id in child_ids:
            children[f"CWE-{child_id} Measure"] = {}
        pique_definition_file_location["factors"]["product_factors"][f"Product_Factor {node.name}"] = {
            "description": node.description,
            "eval_strategy": "pique.evaluation.DefaultProductFactorEvaluator",
            "children": children
        }

    def get_child_ids(self, node: CWE_NODE, CWEs, child_ids) -> List[str]:
        for child_id in node.children:
            child_ids.append(child_id)
            self.get_child_ids(CWEs[child_id], CWEs, child_ids)


class MeasureAdderFlat(AddingStrategy):
    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        if "measures" not in pique_definition_file_location:
            raise KeyError("Pique Definition File has no measures section")
        children = {}
        children[f"{node.name} NPM_IMPROVED Diagnostic"] = {}
        children[f"{node.name} Trivy Diagnostic"] = {}
        children[f"{node.name} Grype Diagnostic"] = {}
        pique_definition_file_location["measures"][f"{node.name} Measure"] = {
            "description": node.description,
            "positive": False,
            "utility_function": "pique.evaluation.ProbabilityDensityFunctionUtilityFunction",
            "abstraction" : node.type,
            "children": children
        }

class DiagnosticAdder(AddingStrategy):
    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        if "diagnostics" not in pique_definition_file_location:
            raise KeyError("Pique Definition File has no diagnostics section")
        tools = ["NPM_IMPROVED", "Grype", "Trivy"]
        for tool in tools:
            node_info = {
                "description" : node.description,
                "toolName" : tool
            }
            pique_definition_file_location["diagnostics"][f"{node.name} {tool} Diagnostic"] = node_info

class MeasureAdder(AddingStrategy):
    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        if "measures" not in pique_definition_file_location:
            raise KeyError("Pique Definition File has no measures section")
        children = {}
        for child in node.children:
            children[f"CWE-{child} Measure"] = {}
        children[f"{node.name} NPM Diagnostic"] = {}
        children[f"{node.name} Trivy Diagnostic"] = {}
        children[f"{node.name} Grype Diagnostic"] = {}

        pique_definition_file_location["measures"][f"{node.name} Measure"] = {
            "description": node.description,
            "positive": False,
            "utility_function": "pique.evaluation.ProbabilityDensityFunctionUtilityFunction",
            "abstraction" : node.type,
            "children": children
        }

class ProductFactorAdder(AddingStrategy):
    def add_node(self, node: CWE_NODE, pique_definition_file_location: Dict):
        if "factors" not in pique_definition_file_location:
            raise KeyError(f"Pique Definition File has no factors section")
        if "product_factors" not in pique_definition_file_location["factors"]:
            raise KeyError(f"Pique Definition File has no product_factors section")
        children = {}
        for child_id in node.children:
            children[f"CWE-{child_id} Measure"] = {}
        pique_definition_file_location["factors"]["product_factors"][f"Product_Factor {node.name}"] = {
            "description": node.description,
            "eval_strategy": "pique.evaluation.DefaultProductFactorEvaluator",
            "children": children
        }


class AddNodesToPiqueDefinition:
    def __init__(self, pique_definition_file: Dict[str, List[CWE_NODE]]) -> None:
        self.pique_definition_file = pique_definition_file

    def add_nodes_to_pique_definition(self, nodes : list[CWE_NODE], addingStrategy : AddingStrategy) -> None:
        for n in nodes:
            addingStrategy.add_node(n, pique_definition_file_location=self.pique_definition_file)