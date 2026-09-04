import logging
from typing import List, Dict, Any, Optional
from backend.attack_surface.models import (
    AttackSurfaceNode,
    AttackSurfaceEdge,
    AttackSurfaceGraph
)

logger = logging.getLogger(__name__)

# Standard Gateway Logical Architecture Layers
DATAFLOW_LAYERS = [
    "CLIENT",
    "GATEWAY_API",
    "SECURITY_PIPELINE",
    "LLM_PROVIDER",
    "STORAGE_INFRA"
]


def build_logical_attack_surface_graph(
    discovered_assets: List[Dict[str, Any]],
    control_coverage_matrix: Optional[List[Dict[str, Any]]] = None
) -> AttackSurfaceGraph:
    """
    Construct a deterministic logical attack surface graph from internal application metadata.
    Zero external network scanning or probing.
    """
    nodes: List[AttackSurfaceNode] = []
    edges: List[AttackSurfaceEdge] = []

    # Map discovered assets to nodes
    for ast in discovered_assets:
        atype = str(ast.get("asset_type", "APPLICATION")).upper()
        crit = str(ast.get("criticality", "HIGH")).upper()
        risk = int(ast.get("risk_score", 0))
        status = str(ast.get("status", "ACTIVE")).upper()

        if atype in ("APPLICATION", "CLIENT"):
            layer = "CLIENT"
        elif atype in ("API", "ENDPOINT"):
            layer = "GATEWAY_API"
        elif atype == "SECURITY_CONTROL":
            layer = "SECURITY_PIPELINE"
        elif atype in ("LLM_MODEL", "LLM_PROVIDER"):
            layer = "LLM_PROVIDER"
        else:
            layer = "STORAGE_INFRA"

        nodes.append(
            AttackSurfaceNode(
                id=ast.get("asset_id", "ast-unknown"),
                name=ast.get("name", "Unnamed Asset"),
                type=atype,
                layer=layer,
                criticality=crit,
                risk_score=risk,
                status=status,
                coverage_pct=float(ast.get("coverage_pct", 100.0))
            )
        )

    # Standard Deterministic Edges representing Gateway Pipeline Architecture
    standard_edges = [
        ("CLIENT", "GATEWAY_API", "Transmits Prompt Payload", "CTRL-AUTH-01"),
        ("GATEWAY_API", "LLM_PROVIDER", "Validates Security Controls & Invokes Model", "CTRL-PI-01"),
        ("LLM_PROVIDER", "STORAGE_INFRA", "Inspects Output & Logs Audit Record", "CTRL-SL-01"),
        ("GATEWAY_API", "STORAGE_INFRA", "Checks Semantic Cache & Rate Limit", "CTRL-CACHE-01")
    ]

    for src_l, tgt_l, rel, ctrl in standard_edges:
        # Connect nodes between adjacent layers
        src_nodes = [n.id for n in nodes if n.layer == src_l]
        tgt_nodes = [n.id for n in nodes if n.layer == tgt_l]
        if src_nodes and tgt_nodes:
            edges.append(
                AttackSurfaceEdge(
                    source=src_nodes[0],
                    target=tgt_nodes[0],
                    relationship=rel,
                    security_control=ctrl
                )
            )

    crit_count = sum(1 for n in nodes if n.criticality == "CRITICAL")
    avg_risk = round(sum(n.risk_score for n in nodes) / len(nodes), 1) if nodes else 0.0

    return AttackSurfaceGraph(
        nodes=nodes,
        edges=edges,
        total_assets=len(nodes),
        critical_assets=crit_count,
        avg_risk_score=avg_risk,
        dataflow_layers=DATAFLOW_LAYERS
    )
