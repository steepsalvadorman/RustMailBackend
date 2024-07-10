use axum::{
    http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method}, middleware, response::IntoResponse, routing::post, Json, Router
};
use axum_server::tls_rustls::RustlsConfig;
use lettre::message::{Message, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use ring::hmac;
use serde::Deserialize;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use hex;

#[tokio::main]
async fn main() {
    // Cargar configuración TLS
    let config = RustlsConfig::from_pem_file(
        "src/certificates/localhost.pem",
        "src/certificates/localhost-key.pem",
    ).await.unwrap();

    // Construir nuestra aplicación con una sola ruta y middleware CORS
    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_static("http://localhost:5173"))
        .allow_methods([Method::POST])
        .allow_headers([CONTENT_TYPE]);

    let app = Router::new()
        .route("/send_email", post(send_email))
        .layer(cors)
        .layer(middleware::map_response(add_security_headers));

    // Ejecutar nuestra app con hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn add_security_headers<B>(mut res: axum::response::Response<B>) -> axum::response::Response<B> {
    res.headers_mut().insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );
    res
}

#[derive(Deserialize)]
struct EmailRequest {
    to: String,
    subject: String,
    nombres: String,
    telefono: String,
    celular: String,
    email: String,
    empresa: String,
    rubro: String,
    ruc: String,
    cargo: String,
    puestos: String,
    tipo_puesto: String,
    mensaje: String,
    secret: String,
}

async fn send_email(Json(payload): Json<EmailRequest>) -> impl IntoResponse {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"your_secret_key");
    let expected_message = b"expected_message";
    
    // Verificar longitud de secret
    if payload.secret.len() % 2 != 0 {
        return "Invalid secret key: length is not even".into_response();
    }

    match hex::decode(&payload.secret) {
        Ok(decoded_secret) => {
            if hmac::verify(&key, expected_message, &decoded_secret).is_err() {
                return "Invalid secret key".into_response();
            }
        },
        Err(_) => {
            return "Invalid secret key: unable to decode".into_response();
        }
    }

    let email_body = format!(
        "Fecha: {}\nFrom: CORPORACION IBGROUP\n\nNombres : {}\nTelefono : {}\nCelular : {}\nEmail : {}\nEmpresa : {}\nRubro : {}\nRUC : {}\nCargo : {}\nPuestos : {}\nTipo de Puesto : {}\nMensaje : {}",
        chrono::Local::now().format("%Y-%m-%d %I:%M %p"),
        payload.nombres,
        payload.telefono,
        payload.celular,
        payload.email,
        payload.empresa,
        payload.rubro,
        payload.ruc,
        payload.cargo,
        payload.puestos,
        payload.tipo_puesto,
        payload.mensaje,
    );

    let email = Message::builder()
        .from("CORPORACION IBGROUP <ibconstruye@corpibgroup.com>".parse().unwrap())
        .to(payload.to.parse().unwrap())
        .subject(payload.subject)
        .singlepart(SinglePart::plain(email_body))
        .unwrap();

    let creds = Credentials::new(
        "stevesalvadorman@gmail.com".to_string(),
        "sdnj eswa ntij ghcr".to_string(),  // Usa la contraseña de la aplicación aquí
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => "Email sent successfully!".into_response(),
        Err(e) => {
            println!("Could not send email: {:?}", e);
            "Could not send email".into_response()
        }
    }
}
