import ctypes, time, struct, hashlib, os, sys, zlib

SO_PATH = os.environ.get("KEM_SO", "/usr/local/lib/libpqc_hqc128.so")  # ruta ABSOLUTA
PK_LEN  = int(os.environ.get("HQC_PK_LEN", "2249"))
SK_LEN  = int(os.environ.get("HQC_SK_LEN", "2305"))

# carga la .so (si falla, revisa ruta o LD_LIBRARY_PATH)
lib = ctypes.CDLL(SO_PATH)

# prototipo: int PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
lib.PQCLEAN_HQC128_CLEAN_crypto_kem_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.PQCLEAN_HQC128_CLEAN_crypto_kem_keypair.restype  = ctypes.c_int

pk = (ctypes.c_ubyte * PK_LEN)()
sk = (ctypes.c_ubyte * SK_LEN)()
rc = lib.PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk)
if rc != 0:
    print("keypair failed", file=sys.stderr); sys.exit(2)

pk_bytes = bytes(bytearray(pk))
sk_bytes = bytes(bytearray(sk))
fp = hashlib.sha256(pk_bytes).digest()
crc = zlib.crc32(pk_bytes) & 0xFFFFFFFF  # CRC-32 estándar

# header binario (LE): magic,version,suite,alg,created,pk_len,fp,crc
hdr = struct.pack("<I H B B Q I 32s I",
                  0x544D454B, 1, 1, 0, int(time.time()), PK_LEN, fp, crc)

out = sys.argv[1] if len(sys.argv) > 1 else "/ws/ardupilot/ROMFS_custom/kemtls/kemtls_pk_default.bin"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "wb") as f:
    f.write(hdr); f.write(pk_bytes)

hdr_sk = struct.pack(
    "<I H B B Q I 32s I",
    0x544D454B, 1, 1, 0, int(time.time()),
    SK_LEN,
    hashlib.sha256(sk_bytes).digest(),
    zlib.crc32(sk_bytes) & 0xFFFFFFFF
)
with open("/ws/ardupilot/ROMFS_custom/kemtls/kemtls_sk_default.bin","wb") as f:
    f.write(hdr_sk); f.write(sk_bytes)

print("Wrote", out, "pk_len=", PK_LEN)

