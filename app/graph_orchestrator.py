# app/graph_orchestrator.py

from langgraph.graph import StateGraph, END
from .models import ScanGraphState, RepoInputModel
from .graph_nodes import (
    initial_setup_node, 
    download_and_unzip_repo_node, # This node handles both download and unzip
    discover_files_node,
    process_discovered_files_node,
    search_compliance_terms_node, # Added new node
    analyze_python_code_node,
    analyze_code_complexity_node, # Changed from calculate_code_analysis_score_node
    summarize_documentation_node, # Import the new node
    classify_risk_tier_node, # Import the new node
    generate_compliance_checklist_node, # Changed from lookup_checklist_node
    prepare_final_response_node, # Import the new node
    persist_scan_results_node # Import the persistence node
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
    graph.add_node("search_compliance_terms", search_compliance_terms_node) # Added new node
    graph.add_node("analyze_python_code", analyze_python_code_node)
    graph.add_node("analyze_code_complexity", analyze_code_complexity_node) # Changed node name and function
    graph.add_node("summarize_documentation", summarize_documentation_node) # Add the new node
    graph.add_node("classify_risk_tier", classify_risk_tier_node) # Add the new node
    graph.add_node("generate_compliance_checklist", generate_compliance_checklist_node) # Changed from lookup_checklist
    graph.add_node("prepare_final_response", prepare_final_response_node) # Add the new node
    graph.add_node("persist_scan_results", persist_scan_results_node) # Add the persistence node
    
    # Set the entry point for the graph
    graph.set_entry_point("initial_setup")
    
    # Define the edges between nodes
    graph.add_edge("initial_setup", "download_repo")
    graph.add_edge("download_repo", "discover_files") # Corrected edge
    graph.add_edge("discover_files", "process_discovered_files")
    graph.add_edge("process_discovered_files", "search_compliance_terms") # New edge
    graph.add_edge("search_compliance_terms", "analyze_python_code") # New edge, from search to analyze
    graph.add_edge("analyze_python_code", "analyze_code_complexity") # Changed target node
    graph.add_edge("analyze_code_complexity", "summarize_documentation") # Changed source node
    graph.add_edge("summarize_documentation", "classify_risk_tier") # New edge
    graph.add_edge("classify_risk_tier", "generate_compliance_checklist") # Changed target node name
    graph.add_edge("generate_compliance_checklist", "prepare_final_response") # Changed source node name
    graph.add_edge("prepare_final_response", "persist_scan_results") # Edge to persistence
    graph.add_edge("persist_scan_results", END) # Edge from persistence to END
    
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
