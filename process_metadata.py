import os
import pymongo
from dotenv import load_dotenv
from poseidon_py.poseidon_hash import poseidon_hash_single, poseidon_hash_many
from ezodf import opendoc

# Load environment variables
load_dotenv()

# MongoDB connection URL
MONGODB_URL = os.getenv("MONGODB_URL")

# Read metadata from ODS file
def read_metadata(file_path):
    doc = opendoc(file_path)
    sheet = doc.sheets[0]
    metadata_list = []

    # Skip header row by using `enumerate` and skipping the first iteration
    for i, row in enumerate(sheet.rows()):
        if i == 0:
            continue  # Skip header row
        cells = row[:8]
        values = [cell.plaintext() if cell else "" for cell in cells]
        metadata = {
            "token_id": int(values[0]),
            "person_name": values[1],
            "birthplace": values[2],
            "ethnicity": values[3],
            "occupation": values[4],
            "special_trait": values[5] if len(values) > 5 else ""
        }
        metadata_list.append(metadata)
    return metadata_list

# Generate Poseidon hash
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

# Compute Merkle Root
def compute_merkle_root(hashes):
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:  # if odd number of elements, duplicate the last element
            hashes.append(hashes[-1])
        new_level = []
        for i in range(0, len(hashes), 2):
            new_level.append(poseidon_hash_single(hashes[i] + hashes[i+1]))
        hashes = new_level
    return hashes[0]

# Convert large integer to felt252 (hex string format within 31 characters)
def to_felt252(value):
    felt252_max_digits = 77  # max digits for a 252-bit integer in decimal
    felt252_str = str(value)  # Convert to string
    return felt252_str.zfill(felt252_max_digits)[:felt252_max_digits]

# Store metadata in MongoDB
def store_in_mongodb(metadata_list, merkle_root):
    client = pymongo.MongoClient(MONGODB_URL)
    db = client["nft_database"]
    collection = db["metadata"]

    # Clear the collection before storing new data
    collection.delete_many({})

    for metadata in metadata_list:
        metadata["merkle_root"] = to_felt252(merkle_root)  # Convert to felt252
        metadata["hash"] = to_felt252(metadata["hash"])    # Convert to felt252
        collection.insert_one(metadata)

def main():
    file_path = "metadata_updated.ods"
    metadata_list = read_metadata(file_path)

    hashes = []
    for metadata in metadata_list:
        metadata_hash = generate_hash(metadata)
        metadata["hash"] = metadata_hash
        hashes.append(metadata_hash)

    merkle_root = compute_merkle_root(hashes)
    store_in_mongodb(metadata_list, merkle_root)
    print(f"Merkle Root: {merkle_root}")

if __name__ == "__main__":
    main()
