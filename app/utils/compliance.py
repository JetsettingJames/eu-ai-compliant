"""
Compliance Utilities

This module provides utilities for working with compliance data,
including loading obligations, determining risk tiers, and generating checklists.
All compliance jargon and configuration is loaded from YAML files.
"""
import logging
from typing import Dict, Any, List, Optional
from app.models import ComplianceChecklistItem, CodeSignal, GrepSignalItem, RiskTier
from app.utils.yaml_config import (
    get_obligations,
    get_obligations_for_tier,
    get_high_risk_signals,
    get_prohibited_signals,
    get_signal_libraries
)

logger = logging.getLogger(__name__)


def load_and_get_checklist_for_tier(tier: str, obligations_data: Optional[Dict[str, Any]] = None) -> List[ComplianceChecklistItem]:
    """
    Loads compliance checklist items for a specific risk tier from the YAML file.
    
    Args:
        tier: The risk tier (prohibited, high, limited, minimal)
        obligations_data: Optional pre-loaded obligations data
        
    Returns:
        List of ComplianceChecklistItem objects for the specified tier
    """
    logger.info(f"Loading checklist items for tier: {tier}")
    
    # Use provided obligations data or load from YAML
    if not obligations_data:
        obligations_data = get_obligations()
    
    # Get tier data from the obligations data
    tier_data = obligations_data.get(tier, {})
    if not tier_data:
        logger.warning(f"No data found for tier: {tier}. Returning empty checklist.")
        return []
    
    # Get obligations for the specified tier
    obligations = tier_data.get("obligations", [])
    if not obligations:
        logger.warning(f"No obligations found for tier: {tier}. Returning empty checklist.")
        return []
    
    checklist_items = []
    
    # Process each obligation in the tier
    for obligation in obligations:
        try:
            checklist_item = ComplianceChecklistItem(
                id=obligation.get("id", ""),
                title=obligation.get("title", ""),
                description=obligation.get("title", ""),  # Use title as description if not provided
                reference_article=obligation.get("ref"),
                category_type=obligation.get("category", "")
            )
            checklist_items.append(checklist_item)
        except Exception as e:
            logger.warning(f"Could not parse checklist item {obligation.get('id', 'Unknown ID')} for tier {tier}: {e}. Skipping item.")
    
    logger.info(f"Loaded {len(checklist_items)} checklist items for tier '{tier}'.")
    return checklist_items


def determine_risk_tier(
    doc_summary_bullets: Optional[List[str]],
    code_signals: Optional[CodeSignal],
    grep_signals: Optional[List[GrepSignalItem]],
    llm_confidence_threshold: float = 0.8
) -> str:
    """
    Determines the risk tier based on documentation summary, code signals, and grep signals.
    
    Args:
        doc_summary_bullets: List of documentation summary bullet points
        code_signals: Code signals from AST analysis
        grep_signals: Grep signals from keyword search
        llm_confidence_threshold: Confidence threshold for LLM-based classification
        
    Returns:
        Risk tier as a string (prohibited, high, limited, minimal, unknown)
    """
    logger.info("Determining risk tier based on summary, code signals, and grep signals...")
    
    # Get signals from YAML configuration
    prohibited_signals = get_prohibited_signals()
    high_risk_signals = get_high_risk_signals()
    signal_libraries = get_signal_libraries()
    
    # Helper to check keywords in various sources
    def check_keywords_in_text(text: str, keywords: List[str]) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        return any(keyword.lower() in text_lower for keyword in keywords)
    
    # Check for prohibited signals in documentation
    if doc_summary_bullets:
        doc_text = " ".join(doc_summary_bullets)
        for signal in prohibited_signals:
            if check_keywords_in_text(doc_text, [signal]):
                logger.info(f"PROHIBITED risk signal '{signal}' found in documentation.")
                return RiskTier.PROHIBITED.value
    
    # Check for prohibited signals in code
    if code_signals:
        # Check for biometric identification in public spaces
        if code_signals.biometric and grep_signals:
            for grep_item in grep_signals:
                if check_keywords_in_text(grep_item.line_content, ["public", "space"]):
                    logger.info("PROHIBITED risk signal: Biometric identification in public spaces detected.")
                    return RiskTier.PROHIBITED.value
    
    # Check for high risk signals in documentation
    if doc_summary_bullets:
        doc_text = " ".join(doc_summary_bullets)
        for signal in high_risk_signals:
            if check_keywords_in_text(doc_text, [signal]):
                logger.info(f"HIGH risk signal '{signal}' found in documentation.")
                return RiskTier.HIGH.value
    
    # Check for high risk signals in code
    if code_signals:
        # Check for critical infrastructure management
        if grep_signals:
            for grep_item in grep_signals:
                if check_keywords_in_text(grep_item.line_content, ["critical", "infrastructure"]):
                    logger.info("HIGH risk signal: Critical infrastructure management detected.")
                    return RiskTier.HIGH.value
    
    # Check for limited risk signals
    if code_signals:
        # Check for emotion recognition
        if grep_signals:
            for grep_item in grep_signals:
                if check_keywords_in_text(grep_item.line_content, ["emotion", "recognition"]):
                    logger.info("LIMITED risk signal: Emotion recognition detected.")
                    return RiskTier.LIMITED.value
        
        # Check for GPAI usage
        if code_signals.uses_gpai:
            logger.info("General Purpose AI / LLM usage detected, typically LIMITED risk (due to transparency).")
            return RiskTier.LIMITED.value
    
    logger.info("No specific prohibited, high, or limited risk signals identified. Classifying as MINIMAL risk.")
    return RiskTier.MINIMAL.value
