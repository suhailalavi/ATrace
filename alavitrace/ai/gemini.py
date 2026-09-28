import os
import json
import logging
from typing import Dict, Any, Optional
from google import genai
from google.genai import types

from alavitrace.ai.base import AIProvider
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.ai.prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger("ATrace")

class GeminiAIProvider(AIProvider):
    """
    AI Security Analysis provider interfacing with Google Gemini API via google-genai SDK.
    """

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-3.8-flash"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name

    def analyze_security_data(self, structured_input: Dict[str, Any]) -> AIAnalysisResult:
        if not self.api_key:
            logger.info("GEMINI_API_KEY environment variable is missing. AI analysis will be skipped.")
            return AIAnalysisResult(
                is_available=False,
                error_message="GEMINI_API_KEY environment variable not configured."
            )

        try:
            logger.info(f"Initializing Gemini Client ({self.model_name})...")
            client = genai.Client(api_key=self.api_key)

            input_json_str = json.dumps(structured_input, indent=2)
            user_prompt = build_user_prompt(input_json_str)

            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                response_mime_type="application/json"
            )

            logger.info("Sending structured security evidence to Gemini for analysis...")
            response = client.models.generate_content(
                model=self.model_name,
                contents=user_prompt,
                config=config
            )

            response_text = response.text.strip() if response.text else ""
            if not response_text:
                return AIAnalysisResult(
                    is_available=False,
                    error_message="Gemini API returned an empty response."
                )

            # Strip markdown formatting if present
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]

            data = json.loads(response_text.strip())

            return AIAnalysisResult(
                executive_summary=data.get("executive_summary", ""),
                attack_surface_summary=data.get("attack_surface_summary", ""),
                key_observations=data.get("key_observations", []),
                investigation_priorities=data.get("investigation_priorities", []),
                remediation_summary=data.get("remediation_summary", []),
                limitations=data.get("limitations", []),
                is_available=True,
                error_message=None
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Gemini API JSON response: {e}")
            return AIAnalysisResult(
                is_available=False,
                error_message=f"Failed to parse structured JSON from Gemini API: {e}"
            )
        except Exception as e:
            logger.warning(f"Gemini API analysis encountered an error: {e}")
            return AIAnalysisResult(
                is_available=False,
                error_message=f"Gemini API analysis failed: {e}"
            )
