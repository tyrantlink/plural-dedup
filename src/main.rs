use std::{sync::Arc, time::Duration};


use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tokio::time::sleep;


struct AppState {
    forward_url: String,
    interaction_url: String,
    hash_store: Arc<DashMap<String, ()>>,
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

    let forward_url = format!(
        "{}{}",
        (
            if request.uri().path().contains("interaction") {
                state.interaction_url.clone()
            } else {
                state.forward_url.clone()
            }
        ).trim_end_matches('/'),
        request.uri().to_string()
    );

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
    let interaction_url = std::env::var("INTERACTION_URL")
        .expect("INTERACTION_URL environment variable must be set");
    let master_token = std::env::var("MASTER_TOKEN")
        .expect("MASTER_TOKEN environment variable must be set");

    let app_state = web::Data::new(AppState {
        forward_url,
        interaction_url,
        hash_store: Arc::new(DashMap::new()),
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
