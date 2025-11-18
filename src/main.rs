use ml_dsa::{
    KeyGen,
    MlDsa65,
    signature::{Keypair, Signer, Verifier},
};
use rand::thread_rng;
use std::fs::File;
use std::io::Write;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 生成 ML-DSA-65（Dilithium3 等级）的密钥对
    let mut rng = thread_rng();
    let kp: ml_dsa::KeyPair<MlDsa65> = MlDsa65::key_gen(&mut rng);

    let signing_key = kp.signing_key();
    let verifying_key = kp.verifying_key();

    // 2. 做一次测试签名
    let message = b"hello dilithium / ML-DSA!";
    let signature = signing_key.sign(message);

    // 3. 验证签名
    verifying_key
        .verify(message, &signature)
        .expect("signature verification failed");
    println!("✅ signature verified OK");

    // 4. 序列化（编码）公钥/私钥，得到定长 byte array
    let sk_bytes = signing_key.encode();      // EncodedSigningKey<MlDsa65>
    let pk_bytes = verifying_key.encode();    // EncodedVerifyingKey<MlDsa65>

    // 5. 写入二进制文件（注意：真实系统中私钥文件要妥善保护！）
    write_binary("mldsa65_secret.key", sk_bytes.as_slice())?;
    write_binary("mldsa65_public.key", pk_bytes.as_slice())?;

    // 6. 同时打印 Base64，方便你复制到网站或配置文件
    let sk_b64 = general_purpose::STANDARD.encode(sk_bytes);
    let pk_b64 = general_purpose::STANDARD.encode(pk_bytes);
    let sig_b64 = general_purpose::STANDARD.encode(signature.encode());

    println!("ML-DSA-65 (CRYSTALS-Dilithium) keys generated.");
    println!("Public key  (Base64):\n{}\n", pk_b64);
    println!("Secret key  (Base64):\n{}\n", sk_b64);
    println!("Signature   (Base64):\n{}\n", sig_b64);

    Ok(())
}

fn write_binary(path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(data)?;
    Ok(())
}
