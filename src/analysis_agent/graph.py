"""LangGraph StateGraph definition.

Flow:
  START
    → file_explorer          (sequential: gathers file tree & key files)
    → index_builder          (sequential: tree-sitter parse → embed → ChromaDB)
    → [language_analyzer,    (parallel fan-out from index_builder)
       build_analyzer,
       artifact_analyzer,
       tactic_classifier]
    → aggregator             (fan-in: merges all outputs)
    → END
"""

from langgraph.graph import END, START, StateGraph

from analysis_agent.nodes.aggregator import aggregator_node
from analysis_agent.nodes.artifact_analyzer import artifact_analyzer_node
from analysis_agent.nodes.build_analyzer import build_analyzer_node
from analysis_agent.nodes.file_explorer import file_explorer_node
from analysis_agent.nodes.index_builder import index_builder_node
from analysis_agent.nodes.language_analyzer import language_analyzer_node
from analysis_agent.nodes.tactic_classifier import tactic_classifier_node
from analysis_agent.state import AnalysisState


def build_graph():
    g = StateGraph(AnalysisState)

    g.add_node("file_explorer",      file_explorer_node)
    g.add_node("index_builder",      index_builder_node)
    g.add_node("language_analyzer",  language_analyzer_node)
    g.add_node("build_analyzer",     build_analyzer_node)
    g.add_node("artifact_analyzer",  artifact_analyzer_node)
    g.add_node("tactic_classifier",  tactic_classifier_node)
    g.add_node("aggregator",         aggregator_node)

    # Sequential entry: START → file_explorer → index_builder
    g.add_edge(START,          "file_explorer")
    g.add_edge("file_explorer", "index_builder")

    # Fan-out: index_builder → 4 parallel analyzers
    g.add_edge("index_builder", "language_analyzer")
    g.add_edge("index_builder", "build_analyzer")
    g.add_edge("index_builder", "artifact_analyzer")
    g.add_edge("index_builder", "tactic_classifier")

    # Fan-in: all 4 → aggregator (LangGraph waits for all predecessors)
    g.add_edge("language_analyzer",  "aggregator")
    g.add_edge("build_analyzer",     "aggregator")
    g.add_edge("artifact_analyzer",  "aggregator")
    g.add_edge("tactic_classifier",  "aggregator")

    g.add_edge("aggregator", END)

    return g.compile()


analysis_graph = build_graph()
