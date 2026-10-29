import argparse
from aegisops.copilot.ingestion import ingest_dataset
from aegisops.copilot.retriever import SemanticIndex

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage AegisOps Copilot dataset and vector index")
    parser.add_argument("--ingest", action="store_true", help="Ingest CSV dataset into SQLite knowledge store")
    parser.add_argument("--index", action="store_true", help="Build or refresh ChromaDB semantic index")
    parser.add_argument("--source", type=str, default=None, help="Path to source CSV directory")
    parser.add_argument("--db", type=str, default=None, help="Path to target SQLite DB")
    parser.add_argument("--force", action="store_true", help="Force rebuild even if content hash matches")
    args = parser.parse_args()

    # If neither --ingest nor --index is explicitly specified, default to running ingestion
    run_ingest = args.ingest or not args.index
    run_index = args.index

    if run_ingest:
        rep = ingest_dataset(source_dir=args.source, db_path=args.db, force=args.force)
        print(rep.summary())

    if run_index:
        idx = SemanticIndex()
        res = idx.build_index(source_dir=args.source, db_path=args.db, force=args.force)
        print(
            f"Semantic index ready: status={res.get('status', 'indexed')}, "
            f"doc_count={res.get('doc_count')}, embedding_provider={res.get('embedding_provider')}"
        )
