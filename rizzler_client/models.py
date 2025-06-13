# --- START OF FILE models.py ---

import os
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import logging
from typing import List, Dict, Any, Optional
from icecream import ic

logger = logging.getLogger(__name__) # Standard logger for this module
load_dotenv()

# Define available models (Display Name: Internal Model ID)
# These are examples; update with actual, tested, and available model IDs.
AVAILABLE_LLM_MODELS = {
    "Gemini 2.0 Flash": "gemini-2.0-flash",
    "Gemini 2.0 Flash Lite": "gemini-2.0-flash-lite",
    "Gemini 2.5 Flash (Latest)": "gemini-2.5-flash-preview-05-20",
    "Gemini 2.5 Flash (Stable)": "gemini-2.5-flash-preview-04-17",
    "Gemini 2.5 Pro (Stable)": "gemini-2.5-pro-preview-05-06",
    "Gemini 2.5 Pro (Latest)": "gemini-2.5-pro-Experimental-03-25"
    # Add more models as they become available or are tested by you
    # "Gemini Previous Stable Flash": "gemini-1.5-flash-preview-0520", 
}
DEFAULT_LLM_MODEL_ID = "gemini-2.5-flash-preview-04-17" # Internal ID for the default model

class Models:
    def __init__(self, model_id: str = DEFAULT_LLM_MODEL_ID):
        """
        Initializes the Models class with a specified Google Generative AI model.

        Args:
            model_id (str): The internal ID of the Google Generative AI model to use.
                            Defaults to DEFAULT_LLM_MODEL_ID.
        """
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            logger.error("GOOGLE_API_KEY not found in environment variables.")
            raise ValueError("GOOGLE_API_KEY not found in environment variables.")

        # Validate the provided model_id against the available models
        if model_id not in AVAILABLE_LLM_MODELS.values():
            logger.warning(
                f"Model ID '{model_id}' not found in predefined AVAILABLE_LLM_MODELS. "
                f"Using default: {DEFAULT_LLM_MODEL_ID}"
            )
            self.current_model_id = DEFAULT_LLM_MODEL_ID
        else:
            self.current_model_id = model_id
        
        self.llm: Optional[ChatGoogleGenerativeAI] = None
        self.executor_llm: Optional[ChatGoogleGenerativeAI] = None
        self._bound_tools_cache: Optional[List[Dict[str, Any]]] = None # To store tools for re-binding

        try:
            self.llm = ChatGoogleGenerativeAI(
                model=self.current_model_id, # Use the validated or default model ID
                google_api_key=google_api_key,
            )
            logger.info(f"Initialized base ChatGoogleGenerativeAI LLM with model: {self.current_model_id}.")
            # Initially, executor_llm is the same as the base llm until tools are bound
            self.executor_llm = self.llm 
        except Exception as e:
            logger.exception(f"Failed to initialize ChatGoogleGenerativeAI with model {self.current_model_id}: {e}")
            # If initialization fails, self.llm and self.executor_llm will remain None or raise the error.
            # Consider how to handle this gracefully in the calling code (e.g., MCPClient).
            raise ValueError(f"Failed to initialize Google LLM (model: {self.current_model_id}): {e}") from e

    def initializeTools(self, toolsList: List[Dict[str, Any]]):
        """
        Binds a list of tools to the current LLM, creating an executor_llm.
        Caches the toolsList for re-binding if the model is switched.

        Args:
            toolsList (List[Dict[str, Any]]): A list of tool schemas to bind.
        
        Raises:
            RuntimeError: If the base LLM (self.llm) is not initialized.
        """
        if not self.llm:
            # This should ideally not happen if __init__ succeeded.
            raise RuntimeError("Base LLM (self.llm) not initialized before calling initializeTools.")
        
        self._bound_tools_cache = toolsList # Cache the tools list for potential re-binding

        try:
            if toolsList:
                self.executor_llm = self.llm.bind_tools(toolsList)
                logger.info(
                    f"Initialized executor_llm (model: {self.current_model_id}) and bound {len(toolsList)} tools."
                )
            else:
                self.executor_llm = self.llm # If no tools, executor is just the base LLM
                logger.warning(
                    f"Initialized executor_llm (model: {self.current_model_id}) without any tools due to empty toolsList."
                )
        except Exception as e:
            logger.exception(f"Failed to initialize/bind tools to executor_llm (model: {self.current_model_id}): {e}")
            # Fallback: executor_llm remains the base LLM without tools
            self.executor_llm = self.llm
            logger.error("Executor LLM set to base LLM due to tool binding failure.")
            # Depending on severity, you might want to re-raise or handle differently.

    def switch_model(self, new_model_id: str) -> bool:
        """
        Switches the active LLM to a new model and re-binds tools if they were previously bound.

        Args:
            new_model_id (str): The internal ID of the new Google Generative AI model to use.

        Returns:
            bool: True if the model was switched successfully, False otherwise.
        """
        if new_model_id == self.current_model_id:
            logger.info(f"Model '{new_model_id}' is already the current active model. No switch needed.")
            return True # No change, but considered successful

        if new_model_id not in AVAILABLE_LLM_MODELS.values():
            logger.error(
                f"Cannot switch to model ID '{new_model_id}': Not found in predefined AVAILABLE_LLM_MODELS."
            )
            return False

        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            logger.error("GOOGLE_API_KEY not found in environment variables. Cannot switch model.")
            return False

        logger.info(f"Attempting to switch LLM from '{self.current_model_id}' to '{new_model_id}'.")
        
        try:
            # Create a new LLM instance for the new model
            new_llm_instance = ChatGoogleGenerativeAI(
                model=new_model_id,
                google_api_key=google_api_key,
            )
            
            # If successful, update self.llm and current_model_id
            self.llm = new_llm_instance
            self.current_model_id = new_model_id
            logger.info(f"Successfully switched base LLM to model: {self.current_model_id}.")

            # Re-bind tools if they were previously cached (i.e., initializeTools was called before)
            if self._bound_tools_cache is not None:
                logger.info(f"Re-binding {len(self._bound_tools_cache)} cached tools to the new model '{self.current_model_id}'.")
                self.initializeTools(self._bound_tools_cache) # This will update self.executor_llm
            else:
                # If no tools were ever bound, the executor_llm is just the new base llm
                self.executor_llm = self.llm
                logger.info(
                    f"Base LLM switched to {self.current_model_id}. No tools were previously bound, "
                    "so executor_llm is now the new base LLM."
                )
            return True # Indicate success
            
        except Exception as e:
            logger.exception(
                f"Failed to switch and re-initialize ChatGoogleGenerativeAI to {new_model_id}. "
                f"Current model remains {self.current_model_id} (or potentially None if initial __init__ failed)."
            )
            # Critical decision: Do we try to revert self.llm to a previous state if it was overwritten before exception?
            # For now, the state might be inconsistent if the ChatGoogleGenerativeAI call itself fails partially.
            # The safest is to indicate failure and let the caller decide how to handle (e.g., re-init MCPClient).
            return False