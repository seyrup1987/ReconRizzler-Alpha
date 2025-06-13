# --- START OF FILE ReconTools/ingest2DB.py ---
import logging
import os
import json
from uuid import uuid4
from typing import List, Dict, Any, Optional
import numpy as np
import faiss
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# --- Configuration ---
DB_PERSIST_DIR = os.path.join(os.path.dirname(__file__), '..', 'db', 'faiss_db')
FALLBACK_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs')), 'failed_ingestions')
os.makedirs(DB_PERSIST_DIR, exist_ok=True)
os.makedirs(FALLBACK_DIR, exist_ok=True)

try:
    # MODIFICATION: Initialize HuggingFaceEmbeddings with all-mpnet-base-v2
    # The HuggingFaceEmbeddings class can load sentence-transformers models.
    # We specify model_kwargs to ensure it runs on CPU if GPU isn't available or desired.
    # Add cache_folder to specify where models are downloaded/cached.
    model_kwargs = {'device': 'cpu'} # Enforce CPU, can be changed to 'cuda' if GPU is available and preferred
    encode_kwargs = {'normalize_embeddings': False} # Normalization can be handled by FAISS if needed (IndexFlatL2 implies L2 norm)
    
    # Define a cache directory for Hugging Face models
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_dir = os.path.join(script_dir, '..', '.hf_cache') # e.g., ReconTools/.hf_cache
    os.makedirs(cache_dir, exist_ok=True)

    SHARED_EMBEDDINGS = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-mpnet-base-v2", # Use the full model name
        model_kwargs=model_kwargs,
        encode_kwargs=encode_kwargs,
        cache_folder=cache_dir
    )
    logger.info("Initialized HuggingFaceEmbeddings with sentence-transformers/all-mpnet-base-v2.")
except Exception as e:
    logger.critical(f"Failed to initialize HuggingFaceEmbeddings: {e}", exc_info=True)
    raise RuntimeError("Embedding initialization failed")

DEFAULT_COLLECTION_NAME = "documents"
RECON_COLLECTION_NAME = "Reconnaissance"

# --- FAISS Store Class ---
class FAISSStore:
    """Manages a FAISS index with associated metadata for a collection."""

    def __init__(self, collection_name: str, dimension: int = 768): # all-mpnet-base-v2 has dimension 768
        self.collection_name = collection_name
        self.dimension = dimension
        self.index = None
        self.metadata = [] # Stores (external_id, Document) tuples
        self.index_path = os.path.join(DB_PERSIST_DIR, f"{collection_name}_index.faiss")
        self.metadata_path = os.path.join(DB_PERSIST_DIR, f"{collection_name}_metadata.json")
        self.reset_index()
        logger.info(f"Initialized FAISSStore for collection '{collection_name}' with dimension {self.dimension}")

    def reset_index(self):
        """Initialize a new FAISS index or load from disk."""
        try:
            if os.path.exists(self.index_path):
                self.index = faiss.read_index(self.index_path)
                logger.info(f"Loaded FAISS index from {self.index_path} with {self.index.ntotal} vectors")
                if self.index.ntotal > 0 and os.path.exists(self.metadata_path):
                    with open(self.metadata_path, 'r', encoding='utf-8') as f:
                        metadata_raw = json.load(f)
                        self.metadata = []
                        for item in metadata_raw:
                            meta_content = item.get('metadata', {})
                            if isinstance(meta_content.get("structured_data"), str):
                                try:
                                    meta_content["structured_data"] = json.loads(meta_content["structured_data"])
                                except json.JSONDecodeError:
                                     logger.warning(f"Could not decode stored structured_data string for id {item.get('id')} in {self.collection_name}. Keeping as string.")
                            self.metadata.append(
                                (item['id'], Document(page_content=item['page_content'], metadata=meta_content))
                            )
                        logger.info(f"Loaded {len(self.metadata)} metadata entries from {self.metadata_path}")
                        if len(self.metadata) != self.index.ntotal:
                            logger.warning(f"Metadata count ({len(self.metadata)}) mismatches index count ({self.index.ntotal}) in {self.collection_name}. Resetting index/metadata.")
                            self.metadata = []
                            self.index = faiss.IndexFlatL2(self.dimension)
                elif self.index.ntotal == 0 or not os.path.exists(self.metadata_path):
                    self.index = faiss.IndexFlatL2(self.dimension)
                    self.metadata = []
                    logger.debug(f"Index loaded but empty or metadata missing for '{self.collection_name}', reset index/metadata.")
            else:
                self.index = faiss.IndexFlatL2(self.dimension)
                self.metadata = []
                logger.debug(f"Created new FAISS index for '{self.collection_name}'")
        except Exception as e:
            logger.error(f"Failed to load FAISS index/metadata for '{self.collection_name}': {e}", exc_info=True)
            self.index = faiss.IndexFlatL2(self.dimension)
            self.metadata = []

    def save(self):
        """Save FAISS index and metadata to disk."""
        try:
            faiss.write_index(self.index, self.index_path)
            logger.debug(f"Saved FAISS index to {self.index_path} with {self.index.ntotal} vectors")
            metadata_raw = []
            for id_, doc in self.metadata:
                 serializable_meta = doc.metadata.copy()
                 if "structured_data" in serializable_meta and not isinstance(serializable_meta["structured_data"], (dict, list, str, int, float, bool, type(None))):
                      logger.warning(f"Non-serializable type {type(serializable_meta['structured_data'])} found in metadata for ID {id_} in {self.collection_name}. Converting to string.")
                      serializable_meta["structured_data"] = str(serializable_meta["structured_data"])
                 metadata_raw.append({
                     'id': id_,
                     'page_content': doc.page_content,
                     'metadata': serializable_meta
                 })
            with open(self.metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata_raw, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved {len(self.metadata)} metadata entries to {self.metadata_path}")
        except Exception as e:
            logger.error(f"Failed to save FAISS index/metadata for '{self.collection_name}': {e}", exc_info=True)
            
    def delete(self, ids=None):
        """Deletes vectors and metadata."""
        try:
            if ids is None:
                self.index = faiss.IndexFlatL2(self.dimension)
                self.metadata = []
                self.save()
                logger.info(f"Deleted ALL vectors and metadata for collection '{self.collection_name}'")
                return True

            ids_set = set(ids)
            new_metadata = []
            
            current_docs_to_keep = []
            for doc_uuid, doc_obj in self.metadata:
                if doc_uuid not in ids_set:
                    current_docs_to_keep.append(doc_obj)
                    new_metadata.append((doc_uuid, doc_obj))
            
            if len(current_docs_to_keep) == len(self.metadata):
                logger.warning(f"No matching IDs found to delete in '{self.collection_name}' from provided list: {ids}")
                return False

            self.index = faiss.IndexFlatL2(self.dimension) 
            self.metadata = [] 

            if current_docs_to_keep:
                texts_to_readd = [doc.page_content for doc in current_docs_to_keep]
                # ids_to_readd = [meta_item[0] for meta_item in new_metadata] # Not needed for add_documents

                if texts_to_readd: 
                    embeddings = SHARED_EMBEDDINGS.embed_documents(texts_to_readd)
                    embeddings_np = np.array(embeddings, dtype='float32')
                    self.index.add(embeddings_np)
                    self.metadata = new_metadata 
                else: 
                    logger.info(f"All specified documents deleted or list became empty for '{self.collection_name}'. Index is now empty.")
            else: 
                 logger.info(f"All documents deleted from '{self.collection_name}'. Index is now empty.")

            self.save()
            logger.info(f"Rebuilt index for '{self.collection_name}' after deleting IDs. New count: {self.index.ntotal}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete records in collection '{self.collection_name}': {str(e)}", exc_info=True)
            return False

    def add_documents(self, documents: List[Document], ids: List[str]):
        """Add documents to the FAISS index."""
        try:
            if not documents:
                logger.warning(f"No documents provided to add to '{self.collection_name}'")
                return

            texts = [doc.page_content for doc in documents]
            embeddings = SHARED_EMBEDDINGS.embed_documents(texts)
            embeddings_np = np.array(embeddings, dtype='float32')

            if embeddings_np.shape[0] != len(documents) or embeddings_np.shape[1] != self.dimension:
                 raise ValueError(f"Embedding shape {embeddings_np.shape} does not match expected ({len(documents)}, {self.dimension})")
            if np.any(np.isnan(embeddings_np)) or np.any(np.isinf(embeddings_np)):
                 raise ValueError("Embeddings contain NaN or infinite values")

            self.index.add(embeddings_np)
            self.metadata.extend(zip(ids, documents))
            self.save()
            logger.info(f"Added {len(documents)} documents to FAISS index '{self.collection_name}' (total: {self.index.ntotal})")
        except Exception as e:
            logger.error(f"Failed to add documents to FAISS index '{self.collection_name}': {e}", exc_info=True)
            raise

    def query(self, query_texts: List[str], n_results: int = 5) -> Dict[str, Any]:
        """Query the FAISS index."""
        try:
            if not query_texts:
                logger.warning(f"No query texts provided for '{self.collection_name}'")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

            if self.index.ntotal == 0:
                logger.warning(f"FAISS index '{self.collection_name}' is empty. No results available.")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

            query_embedding = SHARED_EMBEDDINGS.embed_query(query_texts[0])
            query_np = np.array([query_embedding], dtype='float32')

            if query_np.shape[1] != self.dimension or np.any(np.isnan(query_np)) or np.any(np.isinf(query_np)):
                logger.error(f"Invalid query embedding shape {query_np.shape} or contains NaN/inf for '{self.collection_name}'")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}
            
            try:
                num_results_requested = int(n_results)
                if num_results_requested <= 0: num_results_requested = 5
            except ValueError:
                num_results_requested = 5
            
            # k for search should not exceed ntotal
            k_search = min(num_results_requested, self.index.ntotal)
            if k_search == 0 and self.index.ntotal > 0: # Edge case if n_results was 0 but index has items
                k_search = 1 # Search for at least 1 if items exist
            elif k_search == 0 and self.index.ntotal == 0: # No items and requesting 0
                 return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}


            distances_faiss, indices_faiss = self.index.search(query_np, k_search)

            results = {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}
            
            for i, faiss_idx in enumerate(indices_faiss[0]):
                if faiss_idx != -1: # Process only if index is not -1 (FAISS uses -1 for padding if k > ntotal)
                    if faiss_idx < len(self.metadata): # Safety check
                        id_, doc = self.metadata[faiss_idx]
                        results['ids'].append(id_)
                        structured_data = doc.metadata.get("structured_data")
                        if structured_data is not None:
                             if isinstance(structured_data, (dict, list)):
                                 results['documents'].append(structured_data)
                             else: # Should ideally not happen if stored correctly
                                  results['documents'].append(doc.page_content) 
                        else:
                            results['documents'].append(doc.page_content) # Fallback to page_content
                        
                        other_metadata = {k: v for k, v in doc.metadata.items() if k != "structured_data"}
                        results['metadatas'].append(other_metadata)
                        
                        if i < len(distances_faiss[0]): # Ensure distance index is valid
                            results['distances'].append(float(distances_faiss[0][i])) # Ensure float
                    else:
                        # This should be rare if faiss_idx != -1 check is primary
                        logger.warning(f"FAISS index {faiss_idx} (not -1) out of range for metadata (len: {len(self.metadata)}) in '{self.collection_name}'")
                # No warning for faiss_idx == -1, it's expected padding.
            
            logger.info(f"Query in '{self.collection_name}' returned {len(results['ids'])} valid results")
            return results
        except Exception as e:
            logger.error(f"Failed to query FAISS index '{self.collection_name}': {e}", exc_info=True)
            return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

    def get_document_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the structured_data for a document by its UUID."""
        for id_val, doc_obj in self.metadata: # self.metadata stores (uuid, Document_instance)
            if id_val == doc_id:
                # The Document object's metadata field holds the full structured data.
                if doc_obj.metadata and "structured_data" in doc_obj.metadata:
                    return doc_obj.metadata.get("structured_data")
                else:
                    logger.warning(f"Document ID '{doc_id}' found, but its metadata does not contain 'structured_data' in '{self.collection_name}'.")
                    return None 
            
        logger.warning(f"Document with ID '{doc_id}' not found in metadata for collection '{self.collection_name}'.")
        return None

# --- FAISS Client Getter ---
def get_faiss_client(collection_name: str) -> Optional[FAISSStore]:
    logger.debug(f"Initializing FAISS client for collection: '{collection_name}'")
    try:
        # The dimension for all-mpnet-base-v2 is 768, which is the default.
        client = FAISSStore(collection_name=collection_name, dimension=768)
        return client
    except Exception as e:
        logger.error(f"Failed to initialize FAISS client for '{collection_name}': {e}", exc_info=True)
        return None

# --- Fallback Save Function ---
def save_to_fallback_file(text: str, metadata: str) -> Dict[str, str]:
    logger.info(f"Saving data to fallback file for source: '{metadata}'")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_metadata = metadata.replace('/', '_').replace('\\', '_').replace(':', '_')
    fallback_filename = f"failed_ingest_{safe_metadata}_{timestamp}.json"
    fallback_path = os.path.join(FALLBACK_DIR, fallback_filename)
    try:
        try:
            data_obj = json.loads(text)
            content_to_save = json.dumps({"source": metadata, "timestamp": datetime.utcnow().isoformat(), "data": data_obj}, indent=2)
        except json.JSONDecodeError:
            content_to_save = json.dumps({"source": metadata, "timestamp": datetime.utcnow().isoformat(), "text": text}, indent=2)
        with open(fallback_path, 'w', encoding='utf-8') as f:
            f.write(content_to_save)
        logger.info(f"Successfully saved fallback file: {fallback_path}")
        return {"status": "success", "fallback_path": fallback_path}
    except Exception as e:
        logger.error(f"Failed to save fallback file '{fallback_path}': {e}", exc_info=True)
        return {"status": "failed", "error": f"Failed to save fallback file: {str(e)}"}

# --- Ingest Single Document ---
async def ingest2DB(text: str, metadata: str):
    logger.warning(f"Using deprecated ingest2DB (single chunk) for metadata: {metadata}")
    vector_store = get_faiss_client(DEFAULT_COLLECTION_NAME)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{DEFAULT_COLLECTION_NAME}'. Cannot ingest.")
        fallback_result = save_to_fallback_file(text, metadata)
        return {'error': 'FAISS initialization failed.', 'fallback': fallback_result}

    unique_id = str(uuid4()) 
    metadata_object = {
        "source": metadata,
        "original_text": text,
        "db_document_id": unique_id 
    }
    text_chunk = Document(page_content=text, metadata=metadata_object)
    
    try:
        vector_store.add_documents(documents=[text_chunk], ids=[unique_id])
        logger.info(f"Successfully ingested document {unique_id} into '{DEFAULT_COLLECTION_NAME}' from source: {metadata}")
        return unique_id
    except Exception as error:
        logger.error(f"Error ingesting document into '{DEFAULT_COLLECTION_NAME}' from source {metadata}: {error}", exc_info=True)
        fallback_result = save_to_fallback_file(text, metadata)
        return {'error': str(error), 'fallback': fallback_result}

# --- Chunk and Ingest Documents ---
async def chunk_and_ingest(
    full_text: str,
    source_metadata: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 150
):
    vector_store = get_faiss_client(DEFAULT_COLLECTION_NAME)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{DEFAULT_COLLECTION_NAME}'. Cannot ingest chunks.")
        fallback_result = save_to_fallback_file(full_text, source_metadata)
        return {'error': 'FAISS initialization failed.', 'fallback': fallback_result}

    separators = ["\n\n", "\n", ". ", " ", ""]
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        is_separator_regex=False,
        separators=separators
    )
    split_texts = text_splitter.split_text(full_text)

    if not split_texts:
        logger.warning(f"No text chunks were generated from source: {source_metadata}")
        return {"chunk_ids": [], "message": "No text chunks generated."}

    documents_to_add = []
    chunk_ids = []
    for i, chunk_text in enumerate(split_texts):
        chunk_id = str(uuid4()) 
        chunk_metadata = {
            "source": source_metadata,
            "chunk_index": i + 1,
            "total_chunks": len(split_texts),
            "db_document_id": chunk_id 
        }
        doc = Document(page_content=chunk_text, metadata=chunk_metadata)
        documents_to_add.append(doc)
        chunk_ids.append(chunk_id)

    try:
        vector_store.add_documents(documents=documents_to_add, ids=chunk_ids)
        logger.info(f"Successfully ingested {len(documents_to_add)} chunks into '{DEFAULT_COLLECTION_NAME}' from source: {source_metadata}")
        return {"chunk_ids": chunk_ids}
    except Exception as error:
        logger.error(f"Error ingesting chunks into '{DEFAULT_COLLECTION_NAME}' from source {source_metadata}: {error}", exc_info=True)
        fallback_result = save_to_fallback_file(full_text, source_metadata)
        return {'error': str(error), 'source': source_metadata, 'fallback': fallback_result}

# --- Query FAISS Index ---
async def queryDB(
    query_texts: List[str],
    n_results: int = 5,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    where: Optional[Dict[str, Any]] = None,
    where_document: Optional[Dict[str, Any]] = None # This parameter is not used by FAISSStore
) -> Optional[Dict[str, Any]]:
    logger.info(f"Initiating query in collection '{collection_name}' with {len(query_texts)} query texts, n_results={n_results}.")
    logger.debug(f"Query texts: {query_texts}, where filter: {where}")

    vector_store = get_faiss_client(collection_name)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{collection_name}'. Cannot query.")
        return None

    try:
        results = vector_store.query(query_texts=query_texts, n_results=n_results) 
        
        if where: # Post-query filtering based on metadata
            logger.debug(f"Applying post-query 'where' filtering on metadata for '{collection_name}': {where}")
            filtered_results_after_where = {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}
            
            for id_val, doc_data, meta_data, dist_val in zip(
                results['ids'], results['documents'], results['metadatas'], results['distances']
            ):
                if all(meta_data.get(k) == v for k, v in where.items()):
                    filtered_results_after_where['ids'].append(id_val)
                    filtered_results_after_where['documents'].append(doc_data) 
                    filtered_results_after_where['metadatas'].append(meta_data) 
                    filtered_results_after_where['distances'].append(dist_val)
                else:
                     logger.debug(f"Item ID {id_val} filtered out by 'where' clause. Metadata: {meta_data}")
            results = filtered_results_after_where 
            logger.info(f"Query in '{collection_name}' returned {len(results['ids'])} results after 'where' filtering")
        else:
             logger.info(f"Query in '{collection_name}' returned {len(results['ids'])} results (no 'where' filter applied)")
        
        final_results = {
            'ids': results['ids'], 
            'documents': [[doc] for doc in results['documents']], # Keep the nested list structure
            'metadatas': [[meta] for meta in results['metadatas']], # Keep the nested list structure
            'distances': results['distances'] 
        }
        return final_results
    except Exception as e:
        logger.error(f"Error during FAISS query or filtering in '{collection_name}': {e}", exc_info=True)
        return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

# --- END OF FILE ReconTools/ingest2DB.py ---