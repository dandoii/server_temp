use chrono::Local;
use crypto_hash::{hex_digest, Algorithm};
use utils::read_server_config;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use warp::{reject, Filter, Rejection, Reply};

mod wallet;
mod utils;
use utils::{LoginRequest, UserData, RegisterRequest, KeyExchangeRequest, CustomError};
use utils::{generate_server_keys, generate_session_key, generate_shared_key, read_usermap, save_usermap, email_lookup};
use wallet::ServerWallet;


#[tokio::main]
async fn main() {
    let server_pub_key = warp::get()
        .and(warp::path("server_key"))
        .and_then(handle_get_server_key);

    let wallet_balance = warp::get()
        .and(warp::path("wallet_balance"))
        .and_then(handle_get_wallet_balance);
    
    let key_exchange = warp::post()
        .and(warp::path("key_exchange"))
        .and(warp::body::json())
        .and_then(handle_key_exchange);

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and_then(handle_register);

    let login = warp::post()
    .and(warp::path("login"))
    .and(warp::body::json())
    .and_then(handle_login);

    let get_health = warp::get()
    .and(warp::path("health"))
    .and_then(handle_get_health);

        // Check server directories and files
    if !fs::metadata("./Json").is_ok() {
        fs::create_dir("./Json").expect("Failed to create Json directory");
    }

    if !fs::metadata("./Json/UserData").is_ok() {
        fs::create_dir("./Json/UserData").expect("Failed to create Contracts directory");
    }

    if !fs::metadata(&"./Json/user_map.txt").is_ok() {
        match save_usermap(&HashMap::new()){
            Ok(config) => println!("{}", config),
            Err(_) => println!("Unable to create usermap"),
        };
    }

    generate_server_keys();

    // Create a warp filter that includes both the GET and POST routes
    let routes = key_exchange
        .or(register)
        .or(login)
        .or(get_health)
        .or(server_pub_key)
        .or(wallet_balance)
        .recover(handle_custom_rejection)
        .with(warp::cors()
            .allow_methods(vec!["GET", "POST", "OPTIONS"]) // Only allow the methods your server supports
            .allow_headers(vec!["Content-Type", "access-control-allow-methods", "access-control-allow-origin", "authorization", "cache-control", "x-xsrf-token",])
            .allow_any_origin() // Allow requests from any origin (for development/testing)
            .allow_credentials(false), // You may set this to true if needed
        );

     //Start the server on port 8080
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

async fn handle_key_exchange(req: KeyExchangeRequest) -> Result<impl Reply, Rejection> {
    let config = match read_server_config() {
        Ok(config) => config,
        Err(_) => return Err(reject::custom(CustomError { message: "Unable to process request".to_string() }))
    };

    let shared_key = generate_shared_key(req.pub_key, config.priv_key);
    let file_path = format!("./User_Data/{}/session_data.txt", req.username.to_lowercase());
    fs::write(&file_path, shared_key).expect("Failed to write user data to file");
    return Ok(warp::reply::json(&config.pub_key));
}

async fn handle_register(req: RegisterRequest) -> Result<impl Reply, Rejection> {
        println!("Register request received");
        // Read the existing user map
        let mut user_map = match read_usermap() {
            Ok(user_map) => user_map,
            Err(_) => {
                return Err(reject::custom(CustomError { message: "Unable to read user map".to_string()}))
            },
        };
    
        // Check if the username or email exists in the user map
        if user_map.contains_key(&req.username) || user_map.values().any(|v| v.to_lowercase() == req.email.as_str().to_lowercase()){
            return Err(reject::custom(CustomError { message: "Username or email taken".to_string(),}))
        }
    
        // Ensure the user's directory exists or create it
        let user_directory = format!("./Json/UserData/{}", req.username);
        if !fs::metadata(&user_directory).is_ok() {
            fs::create_dir(&user_directory).expect("Failed to create user's directory");
        }
    
        let file_path = format!("./Json/UserData/{}/user_data.txt", req.username.to_lowercase());
        let password_hash = hex_digest(Algorithm::SHA256, req.password.as_bytes());
        let formatted_date_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let session_key =  generate_session_key();
        let user_data = UserData {
            username: req.username.clone(),
            password: password_hash,
            email: req.email.clone(),
            date_created: formatted_date_time,
            session_key: Some(session_key.clone())
        };
    
        // Write user data to a file
        let serialized_user_data = serde_json::to_string(&user_data).expect("Failed to serialize user data");
        fs::write(&file_path, serialized_user_data).expect("Failed to write user data to file");
        println!("Registration complete");

        // Add the username and email pair to the user map
        user_map.insert(req.username.to_string(), req.email.to_string());
    
        // Write the updated user map to the file
        match save_usermap(&user_map) {
            Ok(message) => println!("{}",message),
            Err(_) => {
                return Err(reject::custom(CustomError { message: "Unable to process request".to_string() }))
            },
        };
        println!("Username and email added to the user map.");
    return Ok(warp::reply::json(&session_key));
}

async fn handle_login(req: LoginRequest) -> Result<impl Reply, Rejection> {
    let username =  match email_lookup(&req.username){
        Ok(username) => username,
        Err(_) => return Err(reject::custom(CustomError { message: "Unable to process request".to_string() })),
    };

    let file_path = format!("./Json/UserData/{}/user_data.txt", &username);
    if !fs::metadata(&file_path).is_ok() {
        return Err(reject::custom(CustomError { message: "Unable to process request".to_string() }));
    }
    let user_data_str = match fs::read_to_string(&file_path){
        Ok(user_data_str) => user_data_str,
        Err(_) => return Err(reject::custom(CustomError { message: "Unable to process request".to_string() })),
    };
    let mut data: UserData = match serde_json::from_str(&user_data_str){
        Ok(data) => data,
        Err(_) => return Err(reject::custom(CustomError { message: "Unable to process request".to_string() })),
    };
    let password_hash = hex_digest(Algorithm::SHA256, &req.password.as_bytes());
    if &data.password != &password_hash {
        return Err(reject::custom(CustomError { message: "Unable to process request".to_string() }))
    }
    let session_key =  generate_session_key();
    data.session_key = Some(session_key.clone());
    let serialized_user_data = serde_json::to_string(&data).expect("Failed to serialize user data");
    fs::write(&file_path, serialized_user_data).expect("Failed to write user data to file");
    return Ok(warp::reply::json(&session_key));
}

// Warp get route functions
async fn handle_get_server_key() -> Result<impl Reply, Rejection> {
    let pub_key = match read_server_config() {
        Ok(config) => config.pub_key,
        Err(_) => return Err(reject::custom(CustomError { message: "Unable to process request".to_string() }))
    };

    return Ok(warp::reply::json(&pub_key));
}

async fn handle_get_wallet_balance() -> Result<impl Reply, Rejection> {
    let balance: u64 = 0;
    return Ok(warp::reply::json(&balance));
}

async fn handle_get_health() -> Result<impl Reply, Rejection> {
    return Ok(warp::reply::with_status(warp::reply(), warp::http::StatusCode::OK));
}

async fn handle_custom_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    if let Some(custom_error) = err.find::<CustomError>() {
        // Handle the custom rejection and return a 400 Bad Request response
        let response = warp::reply::with_status(
            warp::reply::html(format!("Bad Request: {}", custom_error)),
            warp::http::StatusCode::BAD_REQUEST,
        );
        Ok(response)
    } else {
        // For other rejections, return a generic 500 Internal Server Error response
        Ok(warp::reply::with_status(
            warp::reply::html("Internal Server Error".to_string()),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}