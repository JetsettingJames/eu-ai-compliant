"""
YAML Configuration Loader

This module provides utilities for loading and accessing YAML configuration files.
"""
import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from functools import lru_cache

logger = logging.getLogger(__name__)

# Define paths to configuration files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RISK_TIERS_PATH = os.path.join(BASE_DIR, "data", "risk_tiers.yaml")
COMPLIANCE_CONFIG_PATH = os.path.join(BASE_DIR, "data", "compliance_config.yaml")
OBLIGATIONS_PATH = os.path.join(BASE_DIR, "data", "obligations.yaml")


@lru_cache(maxsize=None)
def load_yaml_file(file_path: str) -> Dict[str, Any]:
    """
    Load a YAML file and return its contents as a dictionary.
    Uses lru_cache to cache the results for performance.
    
    Args:
        file_path: Path to the YAML file
        
    Returns:
        Dictionary containing the YAML file contents
    """
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Error loading YAML file {file_path}: {str(e)}")
        return {}


def get_risk_tiers() -> Dict[str, Any]:
    """
    Get the risk tiers configuration.
    
    Returns:
        Dictionary containing risk tiers configuration
    """
    config = load_yaml_file(RISK_TIERS_PATH)
    return config.get('risk_tiers', {})


def get_risk_tier_info(tier: str) -> Dict[str, Any]:
    """
    Get information about a specific risk tier.
    
    Args:
        tier: The risk tier identifier (e.g., 'prohibited', 'high', 'limited', 'minimal')
        
    Returns:
        Dictionary containing information about the risk tier
    """
    tiers = get_risk_tiers()
    return tiers.get(tier, {})


def get_risk_tier_names() -> List[str]:
    """
    Get a list of all risk tier identifiers.
    
    Returns:
        List of risk tier identifiers
    """
    return list(get_risk_tiers().keys())


def get_compliance_config() -> Dict[str, Any]:
    """
    Get the general compliance configuration.
    
    Returns:
        Dictionary containing compliance configuration
    """
    return load_yaml_file(COMPLIANCE_CONFIG_PATH)


def get_high_risk_signals() -> List[str]:
    """
    Get the list of signals that indicate potential high-risk classification.
    
    Returns:
        List of high-risk signals
    """
    config = get_compliance_config()
    return config.get('assessment', {}).get('high_risk_signals', [])


def get_prohibited_signals() -> List[str]:
    """
    Get the list of signals that indicate potential prohibited classification.
    
    Returns:
        List of prohibited signals
    """
    config = get_compliance_config()
    return config.get('assessment', {}).get('prohibited_signals', [])


def get_signal_libraries() -> Dict[str, List[str]]:
    """
    Get the mapping of signal types to libraries.
    
    Returns:
        Dictionary mapping signal types to lists of libraries
    """
    config = get_compliance_config()
    return config.get('assessment', {}).get('signal_libraries', {})


def get_documentation_requirements(tier: str) -> List[str]:
    """
    Get the documentation requirements for a specific risk tier.
    
    Args:
        tier: The risk tier identifier
        
    Returns:
        List of documentation requirements
    """
    config = get_compliance_config()
    return config.get('documentation_requirements', {}).get(tier, [])


def get_regulatory_deadlines() -> Dict[str, str]:
    """
    Get the regulatory deadlines.
    
    Returns:
        Dictionary mapping deadline types to dates
    """
    config = get_compliance_config()
    return config.get('regulatory_deadlines', {})


def get_obligations() -> Dict[str, Any]:
    """
    Get the obligations configuration.
    
    Returns:
        Dictionary containing obligations configuration
    """
    return load_yaml_file(OBLIGATIONS_PATH)


def get_obligations_for_tier(tier: str) -> Dict[str, Any]:
    """
    Get the obligations for a specific risk tier.
    
    Args:
        tier: The risk tier identifier
        
    Returns:
        Dictionary containing obligations for the specified tier
    """
    obligations = get_obligations()
    tier_data = obligations.get(tier, {})
    
    # Return the obligations list if it exists, otherwise return an empty dict
    return tier_data.get("obligations", [])
