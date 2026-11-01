import chromadb

client = chromadb.Client()
col = client.create_collection("tickets")
col.add(ids=["t1"], documents=["Rahul Kumar, Aadhaar 2000 0000 0009, wants a refund"],
        embeddings=[[0.1, 0.2, 0.3]], metadatas=[{"email": "rahul.k@example.com", "phone": "+91 98765 43210"}])
print(col.query(query_embeddings=[[0.1, 0.2, 0.3]], n_results=1)["ids"])
