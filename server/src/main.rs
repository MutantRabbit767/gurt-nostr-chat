// for signing
// use secp256k1::{Secp256k1, Message};
use secp256k1::hashes::{sha256, Hash};
use nostr_sdk::util::hex;

use gurtlib::{GurtServer, GurtResponse, GurtError, ServerContext, Result};
use nostr_sdk::prelude::{ Keys, SecretKey };

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct SignatureResponse {
    event: String,
    privkey: String
} 

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt::init();
    
    let server = GurtServer::with_tls_certificates("./cert.pem", "./cert.key.pem")?
        .get("/", |_| async {
            Ok(GurtResponse::ok().with_string_body("<h1>Hello from GURT!</h1>"))
        })
        .get("/generatenostrid", |_| async {
            let keys = Keys::generate();

            let response_json = json!([keys.public_key(), keys.secret_key().to_secret_hex()]);
            
            GurtResponse::ok().with_json_body(&response_json)
        })
        .get("/generatesignature", |context: &ServerContext| {
            let ctx = context.clone();
            async move {
                let body = ctx.text()?;
                let infoShii: SignatureResponse = serde_json::from_str(&body).map_err(|_| GurtError::invalid_message("Invalid JSON"))?;
                
                let secret_key = SecretKey::from_hex(&infoShii.privkey).map_err(|_| GurtError::invalid_message("Invalid JSON"))?;
                let byteSecretKey = secret_key.to_secret_bytes();
                let weirdSecKey: secp256k1::SecretKey = secp256k1::SecretKey::from_byte_array(byteSecretKey).map_err(|_| GurtError::invalid_message("Invalid JSON"))?;
                let secp = secp256k1::Secp256k1::new();
                let keyPair: secp256k1::Keypair = secp256k1::Keypair::from_secret_key(&secp, &weirdSecKey);
                println!("{}", infoShii.event);

                let eventid = sha256::Hash::hash(infoShii.event.as_bytes());
                let eventidHex = hex::encode(eventid.to_byte_array());
                let idByteArray = eventid.to_byte_array();

                let signature = secp.sign_schnorr_no_aux_rand(&idByteArray, &keyPair);

                let response_json = json!([eventidHex, hex::encode(signature.to_byte_array())]);

                GurtResponse::ok().with_json_body(&response_json)
            }
        });
    
    println!("Starting GURT server on gurt://127.0.0.1:4878");
    
    server.listen("127.0.0.1:4878").await
}