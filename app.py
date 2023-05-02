import hashlib
import bech32


# Step 1: Decode the address
address = 'bc1qqnyt9pdsdx9uue6cwyjgcwxnl2les7lvu8t0ve'
decoded = bech32.decode('bc', address)
print('Decoded address:', decoded)

# Step 2: Get the data payload from the decoded address
data = bytes(decoded[1])
print('Data payload:', data)

# Step 3: Remove the checksum from the data payload
data = data[:-6]
print('Data payload without checksum:', data)

# Step 4: Decode the data payload from base32 and get the raw bytes
raw_bytes = bech32.convertbits(data, 5, 8, False)
print('Raw bytes:', raw_bytes)

# Check if raw_bytes is NoneType
if raw_bytes is None:
    print('Error: Failed to decode the data payload')
    exit()


# Step 5: Remove the first byte (version byte) from the raw bytes
raw_bytes = raw_bytes[1:]
print('Raw bytes without version byte:', raw_bytes)

# Step 6: Hash the raw bytes with SHA256
sha256 = hashlib.sha256()
sha256.update(raw_bytes)
hashed = sha256.digest()
print('Hashed result of raw bytes (SHA256):', hashed.hex())

# Step 7: Hash the result of Step 6 with RIPEMD-160
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(hashed)
hashed = ripemd160.digest()
print('Hashed result of Step 6 (RIPEMD-160):', hashed.hex())

# Step 8: Add the version byte (0x00) to the hashed result from Step 7
hashed = b'\x00' + hashed
print('Hashed result with version byte:', hashed.hex())

# Step 9: Hash the result of Step 8 twice with SHA256
sha256 = hashlib.sha256()
sha256.update(hashed)
hashed = sha256.digest()
sha256 = hashlib.sha256()
sha256.update(hashed)
hashed = sha256.digest()
print('Double hashed result of Step 8 (SHA256):', hashed.hex())

# Step 10: Take the first 4 bytes of the result of Step 9 as the checksum
checksum = hashed[:4]
print('Checksum:', checksum.hex())

# Step 11: Concatenate the result of Step 8 and the result of Step 10
hashed = hashed[:-4]
pubkey_hash = hashed.hex()
print('Pubkey hash:', pubkey_hash)

# Step 12: Add the checksum to the end of the result of Step 11
pubkey_hash_with_checksum = pubkey_hash + checksum.hex()
print('Pubkey hash with checksum:', pubkey_hash_with_checksum)

# Step 13: Convert the result of Step 12 to base58
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base58_string = ''
value = int(pubkey_hash_with_checksum, 16)
while value > 0:
    value, remainder = divmod(value, 58)
    base58_string = alphabet[remainder] + base58_string
print('Base58 encoded address:', base58_string)

# Step 14: Add leading zeros for each leading zero byte in the hashed result from Step 8
leading_zeros = len(hashed) - len(hashed.lstrip(b'\x00'))
public_key = '0' * leading_zeros + pubkey_hash_with_checksum
print('Public key with leading zeros:', public_key)

# Step 15: Encode the public key as bytes
public_key_bytes = bytes.fromhex(public_key)

# Step 16: Compress the public key if the y-coordinate is even
if public_key_bytes[0] == 4:
    x_str = public_key[2:66]
    y_str = public_key[66:]
    x = int(x_str, 16)
    y = int(y_str, 16)
    if y % 2 == 0:
        prefix = b'\x02'
    else:
        prefix = b'\x03'
    compressed_public_key = prefix + x.to_bytes(32, 'big')
    public_key_bytes = compressed_public_key

# Step 17: Encode the compressed public key as hex
public_key_hex = public_key_bytes.hex()

print('Public key:', public_key_hex)
