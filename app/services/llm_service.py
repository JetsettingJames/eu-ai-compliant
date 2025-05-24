# This file will contain functions for interacting with the LLM (e.g., OpenAI GPT models).
# For example:
# - Function to summarize documentation.
# - Function to infer missing fields based on context.

import openai
from openai import AsyncOpenAI # For async calls
import json
from typing import List, Dict, Any, Optional
import httpx
import inspect

from app.config import settings
from app.logger import get_logger
from ..models import CodeSignal, RiskTier

logger = get_logger(__name__)
logger_llm = get_logger(__name__)

# Ensure the API key is loaded when the module is imported
if not settings.OPENAI_API_KEY:
    logger.warning("OPENAI_API_KEY not found in environment settings. LLM calls will fail.")
    # raise ValueError("OPENAI_API_KEY not set") # Or handle gracefully

class LLMService:
    MAX_TOKENS_SUMMARY = settings.LLM_MAX_TOKENS
    SUMMARY_MODEL = settings.OPENAI_MODEL_NAME

    def __init__(self, api_key: Optional[str] = settings.OPENAI_API_KEY):
        if api_key:
            # Create a custom httpx client without any proxy settings
            # This addresses potential issues in environments with system-wide proxies
            custom_httpx_client = httpx.AsyncClient() 
            self.aclient = AsyncOpenAI(
                api_key=api_key,
                timeout=60.0,
                max_retries=2,
                http_client=custom_httpx_client
            )
            logger.info("AsyncOpenAI client initialized in LLMService.")
        else:
            self.aclient = None
            logger.warning("LLMService initialized without an OpenAI API key. API calls will not be made.")

    async def get_llm_summary(
        self,
        markdown_text: str,
        headings: List[str],
        openapi_specs: List[Dict[str, Any]],
        model_name: str = settings.OPENAI_MODEL_NAME # Use the model from settings
    ) -> List[str]:
        """
        Summarizes documentation using an LLM to extract purpose, data, and users.

        Args:
            markdown_text: Combined text from Markdown files.
            headings: List of H1-H3 headings from Markdown.
            openapi_specs: List of summaries from OpenAPI/Swagger files.
            model_name: The OpenAI model to use.

        Returns:
            A list of strings, where each string is a bullet point from the LLM's summary.
            Returns an error message as a single bullet point list on failure.
        """
        if not self.aclient:
            logger.error("OpenAI client not available (API key likely missing). Cannot summarize documentation.")
            return ["Error: OpenAI client not available (API key likely missing)."]

        # Diagnostic logging for httpx - can be removed or reduced once stable
        # try:
        #     sig = inspect.signature(httpx.AsyncClient.__init__)
        #     logger.info(f"DIAGNOSTIC: httpx.AsyncClient.__init__ signature: {sig}")
        #     logger.info(f"DIAGNOSTIC: httpx module location: {inspect.getfile(httpx)}")
        #     logger.info(f"DIAGNOSTIC: httpx version: {httpx.__version__}")
        # except Exception as e:
        #     logger.error(f"DIAGNOSTIC: Error inspecting httpx: {e}")
        
        prompt = _construct_llm_prompt_for_doc_summary(markdown_text, headings, openapi_specs)
        
        logger.info(f"Sending request to OpenAI API (model: {model_name}) for documentation summary.")
        # logger.debug(f"LLM Prompt for doc summary:\n{prompt}") # Can be very verbose

        try:
            response = await self.aclient.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": "You are a helpful AI assistant specialized in analyzing software documentation."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2, # Low temperature for more deterministic and factual summary
                max_tokens=300,  # Max tokens for the summary itself
                top_p=1.0,
                frequency_penalty=0.0,
                presence_penalty=0.0
            )
            
            summary_text = response.choices[0].message.content
            if summary_text:
                # Split into bullet points. LLM is asked to start each with '- '
                bullet_points = [bp.strip() for bp in summary_text.strip().split('\n') if bp.strip().startswith('-')]
                if not bullet_points: # Fallback if LLM doesn't follow format perfectly
                     bullet_points = [summary_text.strip()] # Use the whole text as one point
                logger.info(f"LLM summary received: {bullet_points}")
                return bullet_points
            else:
                logger.warning("LLM returned an empty summary.")
                return ["Warning: LLM returned an empty summary."]

        except openai.APIConnectionError as e:
            logger.error(f"OpenAI API request failed to connect: {e}")
            return [f"Error: OpenAI API connection issue - {e}"]
        except openai.RateLimitError as e:
            logger.error(f"OpenAI API request exceeded rate limit: {e}")
            return [f"Error: OpenAI API rate limit exceeded - {e}"]
        except openai.APIStatusError as e:
            logger.error(f"OpenAI API returned an API Error: Status {e.status_code}, Response: {e.response}")
            return [f"Error: OpenAI API error - Status {e.status_code}"]
        except Exception as e:
            logger.error(f"An unexpected error occurred during summarization: {e}")
            return None

    async def classify_risk_with_llm(
        self,
        doc_summary: Optional[List[str]],
        code_signals: Optional[CodeSignal],
        model_name: str = settings.RISK_CLASSIFICATION_MODEL
    ) -> Optional[str]:
        """Classifies the AI risk tier using an LLM based on document summary and code signals."""
        if not self.aclient:
            logger_llm.error("AsyncOpenAI client not initialized.")
            return None

        if not doc_summary and not code_signals:
            logger_llm.info("No document summary or code signals provided for LLM risk classification.")
            return None # Or a default like RiskTier.UNKNOWN.value if preferred

        prompt_parts = [
            "Based on the following information about a software system, classify its potential risk tier under the EU AI Act.",
            "The available risk tiers are: prohibited, high, limited, minimal, unknown.",
            "Consider the system's purpose, data processed, intended users, and any detected code signals (e.g., use of biometric libraries, general-purpose AI models, live streaming capabilities)."
        ]

        if doc_summary:
            prompt_parts.append("\nDocumentation Summary:")
            for item in doc_summary:
                prompt_parts.append(f"- {item}")
        else:
            prompt_parts.append("\nDocumentation Summary: Not available or not processed.")

        if code_signals:
            prompt_parts.append("\nCode Signals:")
            prompt_parts.append(f"- Biometric-related libraries detected: {code_signals.biometric}")
            prompt_parts.append(f"- Live streaming capabilities detected: {code_signals.live_stream}")
            prompt_parts.append(f"- General-Purpose AI (GPAI) model usage detected: {code_signals.uses_gpai}")
            if code_signals.detected_libraries:
                prompt_parts.append(f"- Other relevant libraries: {', '.join(code_signals.detected_libraries)}")
            else:
                prompt_parts.append("- No other specific sensitive libraries detected by current rules.")
        else:
            prompt_parts.append("\nCode Signals: Not available or not processed.")
        
        prompt_parts.append("\nPlease respond with ONLY ONE of the following risk tiers: prohibited, high, limited, minimal, unknown.")
        prompt_parts.append("For example, if you determine the risk to be high, respond with: high")

        content = "\n".join(prompt_parts)

        try:
            logger_llm.info(f"Sending request to LLM for risk classification. Model: {model_name}")
            # logger_llm.debug(f"Risk classification prompt:\n{content}")
            
            chat_completion = await self.aclient.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert AI Act compliance assistant. Your task is to classify the risk tier of a software system based on provided information. Respond with only one of the specified risk tier labels."
                    },
                    {
                        "role": "user",
                        "content": content,
                    }
                ],
                model=model_name,
                temperature=0.2, # Lower temperature for more deterministic classification
                max_tokens=10 # Expecting a very short response (just the tier name)
            )
            
            response_content = chat_completion.choices[0].message.content
            if response_content:
                # Clean up the response: lowercase and strip whitespace
                # The LLM might sometimes add punctuation or extra words despite instructions.
                tier_str = response_content.strip().lower().replace(".","")
                # Validate if the response is one of the known tiers
                valid_tiers = [tier.value for tier in RiskTier]
                if tier_str in valid_tiers:
                    logger_llm.info(f"LLM classified risk as: {tier_str}")
                    return tier_str
                else:
                    logger_llm.warning(f"LLM returned an unrecognized risk tier: '{response_content}'. Original: '{tier_str}'")
                    # Fallback to unknown if the response is not a valid tier
                    return RiskTier.UNKNOWN.value 
            else:
                logger_llm.warning("LLM returned an empty response for risk classification.")
                return RiskTier.UNKNOWN.value # Fallback for empty response

        except Exception as e:
            logger_llm.error(f"Error during LLM risk classification API call: {e}", exc_info=True)
            return None # Or RiskTier.UNKNOWN.value depending on desired error handling

    async def get_data_governance_insights(
        self, 
        documentation_summary: str, 
        data_governance_obligations: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Analyzes documentation summary for evidence of compliance with data governance obligations."""
        findings: Dict[str, str] = {}
        if not documentation_summary:
            logger_llm.warning("Documentation summary is empty. Cannot perform data governance insights analysis.")
            for obligation in data_governance_obligations:
                findings[obligation['id']] = "Documentation summary was not available for analysis."
            return findings

        logger_llm.info(f"Starting data governance insights analysis for {len(data_governance_obligations)} obligations.")

        for obligation in data_governance_obligations:
            obligation_id = obligation['id']
            obligation_title = obligation['title']
            obligation_desc = obligation['description']

            prompt = (
                f"Review the following AI system documentation summary. Based *only* on this summary, assess if there is evidence addressing the data governance obligation: '{obligation_title} - {obligation_desc}'. "
                f"Focus specifically on whether the documentation mentions or implies practices, features, or statements that fulfill this point. "
                f"Provide a concise assessment (1-2 sentences). If no clear evidence is found, state that. Do not infer information beyond what is present in the summary.\n\n"
                f"Documentation Summary:\n{documentation_summary}\n\n"
                f"Assessment for obligation '{obligation_id} ({obligation_title})':"
            )

            try:
                response = await self.aclient.chat.completions.create(
                    model=self.SUMMARY_MODEL,  
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1, # Low temperature for factual assessment
                    max_tokens=150
                )
                insight = response.choices[0].message.content.strip() if response.choices else "No response from LLM."
            except Exception as e:
                logger_llm.error(f"Error calling LLM for data governance obligation '{obligation_id}': {e}")
                insight = f"Error during analysis: {e}"
            
            findings[obligation_id] = insight
            logger_llm.info(f"LLM response for DG obligation '{obligation_id}': {insight}")
        return findings

    async def get_transparency_insights(self, documentation_summary: str, transparency_obligations: List[Dict[str, Any]]) -> Dict[str, str]:
        """Analyzes documentation summary for evidence of compliance with transparency obligations."""
        findings: Dict[str, str] = {}
        if not documentation_summary:
            logger_llm.warning("Documentation summary is empty. Cannot perform transparency insights analysis.")
            for obligation in transparency_obligations:
                findings[obligation['id']] = "Documentation summary was not available for analysis."
            return findings

        logger_llm.info(f"Starting transparency insights analysis for {len(transparency_obligations)} obligations.")
        for obligation in transparency_obligations:
            obligation_id = obligation['id']
            obligation_title = obligation['title']
            obligation_desc = obligation['description']

            prompt = (
                f"Review the following AI system documentation summary. Based *only* on this summary, assess if there is evidence addressing the transparency obligation: '{obligation_title} - {obligation_desc}'. "
                f"Focus specifically on whether the documentation mentions or implies practices, features, or statements that fulfill this point. "
                f"Provide a concise assessment (1-2 sentences). If no clear evidence is found, state that. Do not infer information beyond what is present in the summary.\n\n"
                f"Documentation Summary:\n{documentation_summary}\n\n"
                f"Assessment for obligation '{obligation_id} ({obligation_title})':"
            )

            try:
                response = await self.aclient.chat.completions.create(
                    model=self.SUMMARY_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1, # Low temperature for factual assessment
                    max_tokens=150
                )
                insight = response.choices[0].message.content.strip() if response.choices else "No response from LLM."
            except Exception as e:
                logger_llm.error(f"Error calling LLM for transparency obligation '{obligation_id}': {e}")
                insight = f"Error during analysis: {e}"
            
            findings[obligation_id] = insight
            logger_llm.info(f"LLM response for TR obligation '{obligation_id}': {insight}")
        return findings

    async def get_human_oversight_insights(self, documentation_summary: str, human_oversight_obligations: List[Dict[str, Any]]) -> Dict[str, str]:
        """Analyzes documentation summary for evidence of compliance with human oversight obligations."""
        findings: Dict[str, str] = {}
        if not documentation_summary:
            logger_llm.warning("Documentation summary is empty. Cannot perform human oversight insights analysis.")
            for obligation in human_oversight_obligations:
                findings[obligation['id']] = "Documentation summary was not available for analysis."
            return findings

        logger_llm.info(f"Starting human oversight insights analysis for {len(human_oversight_obligations)} obligations.")
        for obligation in human_oversight_obligations:
            obligation_id = obligation['id']
            obligation_title = obligation['title']
            obligation_desc = obligation['description']

            prompt = (
                f"Review the following AI system documentation summary. Based *only* on this summary, assess if there is evidence addressing the human oversight obligation: '{obligation_title} - {obligation_desc}'. "
                f"Focus specifically on whether the documentation mentions or implies design features, user instructions, or system capabilities that fulfill this point. "
                f"Provide a concise assessment (1-2 sentences). If no clear evidence is found, state that. Do not infer information beyond what is present in the summary.\n\n"
                f"Documentation Summary:\n{documentation_summary}\n\n"
                f"Assessment for obligation '{obligation_id} ({obligation_title})':"
            )

            try:
                response = await self.aclient.chat.completions.create(
                    model=self.SUMMARY_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1, # Low temperature for factual assessment
                    max_tokens=150
                )
                insight = response.choices[0].message.content.strip() if response.choices else "No response from LLM."
            except Exception as e:
                logger_llm.error(f"Error calling LLM for human oversight obligation '{obligation_id}': {e}")
                insight = f"Error during analysis: {e}"
            
            findings[obligation_id] = insight
            logger_llm.info(f"LLM response for HO obligation '{obligation_id}': {insight}")
        return findings

    async def get_risk_tier_classification(self, summary: str, code_analysis_score: Optional[float] = None) -> RiskTier:
        """Classifies the AI system's risk tier based on its summary and code analysis score."""
        logger_llm.info(f"Attempting to classify risk tier. Summary (first 100 chars): '{summary[:100]}...', Code score: {code_analysis_score}")

        # classify_risk_with_llm expects a list of strings for summary.
        # For now, we are not constructing detailed CodeSignal objects here, passing None.
        # The code_analysis_score is not directly used by classify_risk_with_llm in its current form.
        # This might be an area for future enhancement if code signals need to be derived from the score.
        risk_tier_str: Optional[str] = await self.classify_risk_with_llm(
            doc_summary=[summary] if summary else [], 
            code_signals=None # Placeholder, as we don't construct CodeSignal object here
        )

        if risk_tier_str:
            try:
                # Convert the string (e.g., "high") to RiskTier enum member (e.g., RiskTier.HIGH)
                tier_enum = RiskTier(risk_tier_str.lower())
                logger_llm.info(f"Successfully classified risk tier as: {tier_enum.value}")
                return tier_enum
            except ValueError:
                logger_llm.warning(f"LLM returned a string '{risk_tier_str}' that is not a valid RiskTier value. Defaulting to UNKNOWN.")
                return RiskTier.UNKNOWN
        else:
            logger_llm.warning("classify_risk_with_llm returned None. Defaulting to UNKNOWN risk tier.")
            return RiskTier.UNKNOWN


def _construct_llm_prompt_for_doc_summary(
    markdown_text: str, 
    headings: List[str], 
    openapi_specs: List[Dict[str, Any]]
) -> str:
    """Constructs the prompt for the LLM to summarize documentation."""
    
    headings_str = "\n- ".join(headings) if headings else "No specific headings extracted."
    openapi_specs_str = "\n".join([f"- API: {spec.get('title', 'N/A')}, Version: {spec.get('version', 'N/A')}, Description: {spec.get('description', 'N/A')[:200]}..." for spec in openapi_specs]) \
                        if openapi_specs else "No OpenAPI/Swagger specifications found or parsed."

    # Truncate markdown_text if it's excessively long for the prompt, even after individual file capping.
    # OpenAI has token limits (e.g., GPT-4o has a large context window, but still finite)
    # A rough estimate: 1 token ~ 4 chars. 128k tokens for gpt-4o. Let's be conservative.
    # Max prompt length around 100k chars should be safe to leave room for response.
    max_md_chars = 80000 # Approx 20k tokens for this part
    if len(markdown_text) > max_md_chars:
        logger.warning(f"Markdown text length ({len(markdown_text)} chars) exceeds limit for LLM prompt, truncating.")
        markdown_text = markdown_text[:max_md_chars] + "... (truncated due to length)"

    prompt = f"""You are an AI assistant helping to understand a software project's documentation for EU AI Act compliance.
Based on the following documentation excerpts from a GitHub repository, please summarize:
1. The main purpose or function of the software system.
2. The types of data it processes, mentioning if any personal or sensitive data is apparent.
3. The intended users or categories of users for this system.

Please provide your summary as up to five bullet points in total, covering these three aspects. Focus on clarity and conciseness.
If the documentation is insufficient or unclear for any of these aspects, please state that clearly for the respective aspect (e.g., "Purpose: Not clearly stated in the provided documents.").

Your output should be ONLY the bullet points, each starting with '- '. Example:
- Purpose: To provide a platform for X.
- Data: Processes user-generated content including images and text.
- Users: General public and content creators.

DOCUMENTATION PROVIDED:
------------------------
Combined Markdown Content (from READMEs, docs/*.md):
{markdown_text}
------------------------
Extracted H1-H3 Headings:
- {headings_str}
------------------------
OpenAPI/Swagger API Summaries:
{openapi_specs_str}
------------------------

Return ONLY the bullet points as your response.
"""
    return prompt

# Example usage (for testing, typically not here)
# llm_service = LLMService()
