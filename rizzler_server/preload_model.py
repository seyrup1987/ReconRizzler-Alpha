import os
import logging
from langchain_huggingface import HuggingFaceEmbeddings

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("preload_model")

def main():
    logger.info("Starting Hugging Face model pre-loading sequence...")
    try:
        # The cache directory path should align with what's used in ingest2DB.py.
        # ingest2DB.py calculates it as: os.path.join(os.path.dirname(__file__), '..', '.hf_cache')
        # Assuming ingest2DB.py is in /app/ReconTools/, this resolves to /app/.hf_cache
        # So, we use /app/.hf_cache directly here, as WORKDIR is /app.
        cache_dir = "/app/.hf_cache"
        os.makedirs(cache_dir, exist_ok=True)
        logger.info(f"Target cache directory for models: {cache_dir}")

        model_kwargs = {'device': 'cpu'} # Ensure CPU is used for compatibility
        encode_kwargs = {'normalize_embeddings': False}

        logger.info(f"Initializing HuggingFaceEmbeddings with model 'sentence-transformers/all-mpnet-base-v2' to cache folder: {cache_dir}")
        
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-mpnet-base-v2",
            model_kwargs=model_kwargs,
            encode_kwargs=encode_kwargs,
            cache_folder=cache_dir  # Crucial: ensure this path is used
        )
        
        # Perform a dummy embedding operation to trigger the actual download and caching
        logger.info("Attempting to embed a dummy sentence to ensure model is downloaded and cached...")
        dummy_text_to_embed = "Initialize and cache the model."
        embeddings.embed_query(dummy_text_to_embed)
        
        logger.info("Hugging Face model 'sentence-transformers/all-mpnet-base-v2' pre-loading and caching successful.")
        
    except Exception as e:
        logger.error(f"Critical error during model pre-loading: {e}", exc_info=True)
        # Exit with a non-zero status to fail the Docker build if pre-loading fails
        exit(1)

if __name__ == "__main__":
    main()