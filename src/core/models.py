from dataclasses import dataclass
from dataclasses import field
from typing import List, Dict, Union, Optional, Literal
from pydantic import BaseModel, RootModel, Field


@dataclass
class ProjectInfo:
    url: Union[str, int, List, None] = "n/a"
    commit_id: Union[str, int, List, None] = "n/a"
    address: Union[str, int, List, None] = "n/a"
    chain: Union[str, int, List, None] = "n/a"
    compiler_version: Union[str, List, None] = "n/a"
    project_path: Union[str, List, Dict, None] = "n/a"

    def is_empty(self):
        if (self.url == "n/a" and self.address == "n/a") or (
            not self.url and not self.address
        ):
            return True
        return False


@dataclass
class Finding:
    id: Union[str, int] = 0
    category: Dict = field(default_factory=dict)
    title: str = ""
    description: str = ""
    severity: str = ""
    location: Union[str, int, List] = ""
    # contract: Union[str, int, List] = ""
    # function: Union[str, int, List] = ""
    # lineNumber: Union[str, int, List] = ""


@dataclass
class MapReduceResult:
    project_info: ProjectInfo = field(default_factory=ProjectInfo)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class Context:
    """
    The context message that is passed between the different stages of the pipeline.
    """

    index: int = 0
    document: str = ""
    response: str = ""
    length: int = 0


# class CWE:
#     def __init__(
#         self, ID: int, Name: str, Description: str, Abstraction: str, Mapping: str
#     ):
#         self.ID = ID
#         self.Name = Name
#         self.Description = Description
#         self.Abstraction: Literal["Pillar", "Class", "Base", "Variant"] = Abstraction
#         self.Mapping: Literal[
#             "Allowed", "Allowed-with-Review", "Discouraged", "Prohibited"
#         ] = Mapping
#         self.Peer: List["CWE"] = []
#         self.Parent: List["CWE"] = []
#         self.Child: List["CWE"] = []

#     def add_child(self, child_cwe: "CWE"):
#         self.Child.append(child_cwe)
#         child_cwe.Parent.append(self)


class CWE(BaseModel):
    ID: int
    Name: str
    Description: str = ""
    Abstraction: Literal["Pillar", "Class", "Base", "Variant", "Compound"]
    Mapping: Literal["Allowed", "Allowed-with-Review", "Discouraged", "Prohibited"]
    Peer: List = Field(default_factory=list)
    Parent: List = Field(default_factory=list)
    Child: List[int] = Field(default_factory=list)

    def __str__(self) -> str:
        return f"CWE-{self.ID}: {self.Name}"

    def __hash__(self):
        return hash(str(self))

    def add_child(self, child_cwe: "CWE"):
        self.Child.append(child_cwe)
        child_cwe.Parent.append(self)


class CWEDatabase(RootModel):
    root: Dict[str, CWE]

    def get_by_id(self, id: int | str):
        name = f"CWE-{id}"
        return self.root[name]

    def get_by_name(self, name: str):
        return self.root[name]


@dataclass
class Address:
    address: str
    network: str = ""
    account_type: str = ""


@dataclass
class GithubUrl:
    href: str
    git_url: str = ""
    proj: str = ""
    owner: str = ""
    repo: str = ""
    branch: str = ""
    dir_name: str = ""
    file_name: str = ""
    fragment: str = ""


@dataclass
class FetchObject:
    fetcher_name: str
    target: str


class Report(BaseModel):
    path: str = ""
    project_info: ProjectInfo = field(default_factory=ProjectInfo)
    findings: List[Finding] = field(default_factory=list)

    def append_finding(self, finding: Finding):
        self.findings.append(finding)


class History(BaseModel):
    finished: List = []
    failed: List = []


# ──────────────────────────────────────────────
# Discovery Module Models
# ──────────────────────────────────────────────


@dataclass
class StateVariable:
    name: str = ""
    var_type: str = ""
    visibility: str = ""
    mutability: str = ""
    slot_info: str = ""


@dataclass
class FunctionSignature:
    name: str = ""
    visibility: str = ""
    modifiers: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)
    state_mutations: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)
    is_payable: bool = False


@dataclass
class ContractProfile:
    """Deep structural profile of a smart contract."""
    file_path: str = ""
    contract_name: str = ""
    compiler_pragma: str = ""
    is_upgradeable: bool = False
    is_proxy: bool = False
    inheritance_chain: List[str] = field(default_factory=list)
    imported_contracts: List[str] = field(default_factory=list)
    state_variables: List[StateVariable] = field(default_factory=list)
    functions: List[FunctionSignature] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    external_dependencies: List[str] = field(default_factory=list)
    protocol_type: str = ""
    uses_assembly: bool = False
    uses_delegatecall: bool = False
    uses_selfdestruct: bool = False
    uses_create2: bool = False
    token_standards: List[str] = field(default_factory=list)
    raw_source: str = ""


@dataclass
class AttackSurface:
    """Identified attack surface area in a contract."""
    entry_point: str = ""
    surface_type: str = ""
    trust_boundary: str = ""
    value_flow: str = ""
    description: str = ""
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityHypothesis:
    """A reasoned hypothesis about a potential novel vulnerability."""
    id: int = 0
    title: str = ""
    hypothesis: str = ""
    attack_narrative: str = ""
    affected_functions: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    complexity: str = ""
    impact: str = ""
    novelty_reasoning: str = ""
    investigation_steps: List[str] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)


@dataclass
class DiscoveryPrompt:
    """A structured prompt for LLM-driven 0-day discovery."""
    id: int = 0
    category: str = ""
    title: str = ""
    system_context: str = ""
    analysis_prompt: str = ""
    focus_areas: List[str] = field(default_factory=list)
    contract_context: str = ""
    investigation_guide: List[str] = field(default_factory=list)


class DiscoveryReport(BaseModel):
    """Complete output of the discovery pipeline."""
    target_path: str = ""
    contract_profiles: List[Dict] = Field(default_factory=list)
    attack_surfaces: List[Dict] = Field(default_factory=list)
    vulnerability_hypotheses: List[Dict] = Field(default_factory=list)
    discovery_prompts: List[Dict] = Field(default_factory=list)
    meta_analysis: str = ""
    investigation_roadmap: List[str] = Field(default_factory=list)
    guidebook: Optional[Dict] = None


# ──────────────────────────────────────────────
# Adaptive Investigation Engine Models
# ──────────────────────────────────────────────


class EvaluationResult(BaseModel):
    """Self-evaluation of investigation methodology quality."""
    quality_score: float = 0.0
    coverage_gaps: List[str] = Field(default_factory=list)
    depth_issues: List[str] = Field(default_factory=list)
    grounding_failures: List[str] = Field(default_factory=list)
    strengths: List[str] = Field(default_factory=list)
    recommendation: str = ""  # "converge" or "refine"
    iteration: int = 0


class InvestigationGuidebook(BaseModel):
    """
    Final self-validated investigation guidebook.

    This is the primary output of the Adaptive Investigation Engine.
    It contains investigation methodology (prompts + guides) that has
    been self-evaluated and refined until it meets quality standards.
    """
    target_path: str = ""
    protocol_type: str = ""
    # The actual methodology
    investigation_prompts: List[Dict] = Field(default_factory=list)
    reasoning_guides: List[Dict] = Field(default_factory=list)
    # Proof of self-validation
    evaluation_history: List[Dict] = Field(default_factory=list)
    final_quality_score: float = 0.0
    iterations_to_converge: int = 0
    # Grounding evidence
    source_code_hash: str = ""
    dataset_findings_used: int = 0
    # Raw reasoning chain (for transparency)
    understanding: str = ""
    methodology_evolution: List[str] = Field(default_factory=list)
