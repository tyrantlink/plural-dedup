use std::{sync::Arc, time::Duration};


use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use dashmap::DashMap;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use hex::FromHex;
use sha2::{Digest, Sha256};
use tokio::time::sleep;


struct AppState {
    forward_url: String,
    hash_store: Arc<DashMap<String, ()>>,
    discord_public_key: PublicKey,
    master_token: String,
    client: reqwest::Client,
}

enum DiscordEndpointResponse {
    Unauthorized,
    DuplicateEvent,
    Valid
}


fn normalize_sequence(bytes: &[u8]) -> Vec<u8> {
    let pattern = [0x22, 0x73, 0x22, 0x3A]; // "s":
    let mut result = bytes.to_vec();

    if let Some(start_idx) = bytes.windows(4)
        .position(|window| window == pattern) 
    {
        let start_pos = start_idx + 4;
        for i in start_pos..result.len() {
            if result[i] == 0x2C { // ,
                break;
            }
            result[i] = 0x30; // 0
        }
    }

    result
}

fn verify_discord_signature(
    timestamp: &str,
    body: &[u8],
    signature: &str,
    public_key: &PublicKey,
) -> bool {
    let message = format!("{}{}", timestamp, String::from_utf8_lossy(body));

    match Vec::from_hex(signature) {
        Ok(sig_bytes) => {
            if sig_bytes.len() != 64 {
                return false;
            }
            let mut fixed_sig = [0u8; 64];
            fixed_sig.copy_from_slice(&sig_bytes);

            if let Ok(signature) = Signature::from_bytes(&fixed_sig) {
                public_key.verify(message.as_bytes(), &signature).is_ok()
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn discord_endpoint_check(
    request: &HttpRequest,
    body: &[u8],
    state: &web::Data<AppState>
) -> DiscordEndpointResponse {
    if request.method() != reqwest::Method::POST {
        return DiscordEndpointResponse::Valid;
    }

    let path_str = request.uri().path().to_string();

    if !path_str.starts_with("/discord") {
        return DiscordEndpointResponse::Valid;
    }

    let is_discord_webhook = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|ua| ua == "Discord-Webhook/1.0 (+https://discord.com)")
        .unwrap_or(false);

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match (is_discord_webhook, auth_header) {
            (true, None) => {
                let timestamp = request
                    .headers()
                    .get("X-Signature-Timestamp")
                    .and_then(|h| h.to_str().ok());
                let signature = request
                    .headers()
                    .get("X-Signature-Ed25519")
                    .and_then(|h| h.to_str().ok());
    
                match (timestamp, signature) {
                    (Some(ts), Some(sig)) => {
                        if !verify_discord_signature(ts, &body, sig, &state.discord_public_key) {
                            return DiscordEndpointResponse::Unauthorized;
                        }
                    }
                    _ => return DiscordEndpointResponse::Unauthorized,
                }
            }
            (false, Some(token)) => {
                if token != state.master_token {
                    return DiscordEndpointResponse::Unauthorized;
                }
            }
            _ => {},
        }

    if path_str != "/discord/event" {
        return DiscordEndpointResponse::Valid;
    }

    let mut hasher = Sha256::new();
        hasher.update(normalize_sequence(&body));
        let hash = format!("{:x}", hasher.finalize());

        if state.hash_store.contains_key(&hash) {
            return DiscordEndpointResponse::DuplicateEvent;
        }

        state.hash_store.insert(hash.clone(), ());

        let hash_store = Arc::clone(&state.hash_store);
        tokio::spawn(async move {
            sleep(Duration::from_secs(60)).await;
            hash_store.remove(&hash);
        });

    return DiscordEndpointResponse::Valid;

    
}

async fn handle_request(
    request: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    match discord_endpoint_check(&request, &body, &state) {
        DiscordEndpointResponse::Unauthorized => {
            println!("401 {} {}", request.method(), request.uri());
            return Ok(HttpResponse::Unauthorized().finish());
        }
        DiscordEndpointResponse::DuplicateEvent => {
            println!("DUPLICATE {} {}", request.method(), request.uri());
            return Ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body("DUPLICATE_EVENT"));
        }
        DiscordEndpointResponse::Valid => {}
    }

    println!("{} {}", request.method(), request.uri());

    let forward_url = format!("{}{}", state.forward_url.trim_end_matches('/'), request.uri().to_string());

    let mut forward = state.client
        .request(request.method().clone(), &forward_url)
        .body(body.to_vec());

    for (header_name, header_value) in request.headers() {
        if header_name != header::HOST {
            forward = forward.header(header_name, header_value);
        }
    }

    let resp = forward
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .bytes()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let mut builder = HttpResponse::build(status);
    for (name, value) in headers.iter() {
        if name != header::CONTENT_LENGTH {
            builder.insert_header((name.clone(), value.clone()));
        }
    }

    Ok(builder.body(body))

}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let forward_url = std::env::var("FORWARD_URL")
        .expect("FORWARD_URL environment variable must be set");
    let discord_public_key = std::env::var("DISCORD_PUBLIC_KEY")
        .expect("DISCORD_PUBLIC_KEY environment variable must be set");
    let master_token = std::env::var("MASTER_TOKEN")
        .expect("MASTER_TOKEN environment variable must be set");

    let public_key_bytes = <[u8; 32]>::from_hex(discord_public_key)
        .expect("Invalid Discord public key format");
    let discord_public_key = PublicKey::from_bytes(&public_key_bytes)
        .expect("Invalid Discord public key");

    let app_state = web::Data::new(AppState {
        forward_url,
        hash_store: Arc::new(DashMap::new()),
        discord_public_key,
        master_token,
        client: reqwest::Client::new()
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .default_service(web::route().to(handle_request))})
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
