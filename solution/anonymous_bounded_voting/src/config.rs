use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;

lazy_static! {
    pub static ref SIGNATURE_SECP256K1: WedprSecp256k1Recover =
        WedprSecp256k1Recover::default();
    pub static ref HASH_KECCAK256: WedprKeccak256 = WedprKeccak256::default();
}
