import os
import pymongo
from dotenv import load_dotenv
from poseidon_py.poseidon_hash import poseidon_hash_single, poseidon_hash_many

# Load environment variables
load_dotenv()

# MongoDB connection URL
MONGODB_URL = os.getenv("MONGODB_URL")

# Function to generate Poseidon hash
def generate_hash(metadata):
    concatenated = (
        str(metadata["token_id"]).encode() +
        metadata["person_name"].encode() +
        metadata["birthplace"].encode() +
        metadata["ethnicity"].encode() +
        metadata["occupation"].encode() +
        (metadata["special_trait"] or "").encode()
    )
    # Split the concatenated data into chunks that fit within u_int256_t
    chunks = [int.from_bytes(concatenated[i:i+31], 'big') for i in range(0, len(concatenated), 31)]
    hash_value = poseidon_hash_many(chunks)
    return hash_value

# Function to compute Merkle Root
def compute_merkle_root(hashes):
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:  # if odd number of elements, duplicate the last element
            hashes.append(hashes[-1])
        new_level = []
        for i in range(0, len(hashes), 2):
            new_level.append(poseidon_hash_single(hashes[i] + hashes[i+1]))
        hashes = new_level
    return hashes[0]

# Convert large integer to felt252 (decimal string format within 31 characters)
def to_felt252(value):
    felt252_max_digits = 77  # max digits for a 252-bit integer in decimal
    felt252_str = str(value)  # Convert to string
    return felt252_str.zfill(felt252_max_digits)[:felt252_max_digits]

# Function to verify the data in MongoDB
def verify_data():
    client = pymongo.MongoClient(MONGODB_URL)
    db = client["nft_database"]
    collection = db["metadata"]

    metadata_list = list(collection.find({}))
    hashes = []

    for metadata in metadata_list:
        # Regenerate hash from the metadata
        regenerated_hash = generate_hash(metadata)
        stored_hash = int(metadata["hash"])
        
        if regenerated_hash == stored_hash:
            print(f"Hash verification passed for token_id {metadata['token_id']}")
        else:
            print(f"Hash verification failed for token_id {metadata['token_id']}")
        
        hashes.append(regenerated_hash)

    # Compute Merkle root from regenerated hashes
    regenerated_merkle_root = compute_merkle_root(hashes)
    stored_merkle_root = int(metadata_list[0]["merkle_root"])  # Assuming all entries have the same Merkle root

    if regenerated_merkle_root == stored_merkle_root:
        print(f"Merkle root verification passed")
    else:
        print(f"Merkle root verification failed")

def main():
    verify_data()

if __name__ == "__main__":
    main()