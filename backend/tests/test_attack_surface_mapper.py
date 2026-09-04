import pytest
from backend.attack_surface.mapper import (
    build_logical_attack_surface_graph,
    DATAFLOW_LAYERS
)
from backend.services.asset_service import STANDARD_GATEWAY_ASSETS


def test_build_logical_attack_surface_graph():
    graph = build_logical_attack_surface_graph(STANDARD_GATEWAY_ASSETS)

    assert graph.total_assets == len(STANDARD_GATEWAY_ASSETS)
    assert graph.critical_assets >= 3
    assert len(graph.nodes) == len(STANDARD_GATEWAY_ASSETS)
    assert len(graph.edges) >= 3
    assert graph.dataflow_layers == DATAFLOW_LAYERS

    layers = {n.layer for n in graph.nodes}
    assert "CLIENT" in layers
    assert "GATEWAY_API" in layers
    assert "LLM_PROVIDER" in layers
    assert "STORAGE_INFRA" in layers
