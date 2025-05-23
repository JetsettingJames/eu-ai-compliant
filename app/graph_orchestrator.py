# app/graph_orchestrator.py

from langgraph.graph import StateGraph, END
from .models import ScanGraphState, RepoInputModel
from .graph_nodes import (
    initial_setup_node, 
    download_and_unzip_repo_node, # This node handles both download and unzip
    discover_files_node,
    process_discovered_files_node,
    analyze_python_code_node,
    summarize_documentation_node, # Import the new node
    classify_risk_tier_node, # Import the new node
    lookup_checklist_node, # Import the new node
    prepare_final_response_node, # Import the new node
    prepare_persistence_data_node, # Import the new node
    persist_scan_data_node # Import the new node
)
from .logger import get_logger
from typing import Optional

logger_orchestrator = get_logger(__name__)

# Global variable to cache the compiled graph
_compiled_graph: Optional[StateGraph] = None

def get_graph_orchestrator() -> StateGraph:
    """Creates and compiles the LangGraph for repository scanning, caching the compiled graph."""
    global _compiled_graph
    if _compiled_graph is not None:
        logger_orchestrator.info("Returning cached compiled graph.")
        return _compiled_graph

    logger_orchestrator.info("Creating and compiling new graph.")
    # Initialize the graph with the ScanGraphState
    graph = StateGraph(ScanGraphState)
    
    # Add nodes to the graph
    graph.add_node("initial_setup", initial_setup_node)
    graph.add_node("download_repo", download_and_unzip_repo_node) # This node handles both
    graph.add_node("discover_files", discover_files_node)
    graph.add_node("process_discovered_files", process_discovered_files_node)
    graph.add_node("analyze_python_code", analyze_python_code_node)
    graph.add_node("summarize_documentation", summarize_documentation_node) # Add the new node
    graph.add_node("classify_risk_tier", classify_risk_tier_node) # Add the new node
    graph.add_node("lookup_checklist", lookup_checklist_node) # Add the new node
    graph.add_node("prepare_persistence_data", prepare_persistence_data_node) # Add the new node
    graph.add_node("persist_scan_data", persist_scan_data_node) # Add the new node
    graph.add_node("prepare_final_response", prepare_final_response_node) # Add the new node
    
    # Set the entry point for the graph
    graph.set_entry_point("initial_setup")
    
    # Define the edges between nodes
    graph.add_edge("initial_setup", "download_repo")
    graph.add_edge("download_repo", "discover_files") # Corrected edge
    graph.add_edge("discover_files", "process_discovered_files")
    graph.add_edge("process_discovered_files", "analyze_python_code")
    graph.add_edge("analyze_python_code", "summarize_documentation") # New edge
    graph.add_edge("summarize_documentation", "classify_risk_tier") # New edge
    graph.add_edge("classify_risk_tier", "lookup_checklist") # New edge
    graph.add_edge("lookup_checklist", "prepare_persistence_data") # New edge
    graph.add_edge("prepare_persistence_data", "persist_scan_data") # New edge
    graph.add_edge("persist_scan_data", "prepare_final_response") # New edge
    graph.add_edge("prepare_final_response", END) # New edge to END
    
    # Compile the graph
    compiled_graph = graph.compile()
    _compiled_graph = compiled_graph
    return compiled_graph

# Example of how to get the graph (optional, for testing or direct use)
# if __name__ == '__main__':
#     app_graph = get_graph_orchestrator()
#     print("Graph compiled successfully.")
    # To visualize (if graphviz is installed):
    # from langgraph.utils import print_ascii_tree
    # print_ascii_tree(app_graph.get_graph())
    # Or save as image:
    # app_graph.get_graph().draw_png("repo_scan_graph.png")
