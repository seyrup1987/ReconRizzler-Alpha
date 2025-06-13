import logging
import asyncio
from langchain_community.vectorstores import FAISS
from ingest2DB import get_faiss_client, RECON_COLLECTION_NAME

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def flush_recon_database():
    """
    Completely flushes (deletes all data from) the FAISS reconnaissance database collection.
    
    Returns:
        dict: Status of the operation (success or error with details).
    """
    max_retries = 3
    vector_store_recon = None

    # Attempt to get FAISS client
    for attempt in range(max_retries):
        logger.debug(f"Attempt {attempt + 1}/{max_retries} to get FAISS client for '{RECON_COLLECTION_NAME}'")
        vector_store_recon = get_faiss_client(RECON_COLLECTION_NAME)
        if vector_store_recon:
            logger.debug(f"Successfully obtained FAISS client for '{RECON_COLLECTION_NAME}'")
            break
        logger.warning(f"Attempt {attempt + 1}/{max_retries} failed to get FAISS client, retrying...")
        await asyncio.sleep(2 ** attempt)

    if not vector_store_recon:
        logger.error(f"Failed to initialize FAISS client for '{RECON_COLLECTION_NAME}' after {max_retries} attempts")
        return {"status": "error", "message": f"FAISS client initialization failed for {RECON_COLLECTION_NAME}"}

    try:
        # Get all document IDs in the collection
        index = vector_store_recon.index
        if index.ntotal == 0:
            logger.info(f"Collection '{RECON_COLLECTION_NAME}' is already empty")
            return {"status": "success", "message": "Database was already empty"}

        # Delete all documents by reconstructing an empty index
        vector_store_recon.delete()  # Full-flush using custom FAISSStore method
        logger.info(f"Successfully flushed all data from '{RECON_COLLECTION_NAME}'")
        return {"status": "success", "message": f"Flushed all data from {RECON_COLLECTION_NAME}"}

    except Exception as e:
        logger.error(f"Failed to flush '{RECON_COLLECTION_NAME}': {str(e)}", exc_info=True)
        return {"status": "error", "message": f"Failed to flush database: {str(e)}"}

async def main():
    """Main function to run the flush operation."""
    result = await flush_recon_database()
    logger.info(f"Flush operation result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
