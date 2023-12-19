use rand::RngCore;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use warp::reject::Reject;
use std::collections::HashMap;
use std::fs::{self};
use std::path::Path;
use hex::encode;
use hex::FromHex;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use bdk::bitcoin::{Txid,TxIn,TxOut};
use bdk::bitcoin::blockdata::transaction::OutPoint;
use bdk::bitcoin::hashes::Hash;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct KeyExchangeRequest {
    pub username: String,
    pub pub_key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct UserData {
    pub username: String,
    pub email: String,
    pub password : String,
    pub date_created: String,
    pub session_key: Option<String>
}

#[derive(Debug)]
pub struct CustomError {
    pub message: String,
}

impl Reject for CustomError {}
impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    pub pub_key: String,
    pub priv_key: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeedStore{
    pub mnemonic: String
}

pub fn generate_server_keys(){
    let mut rng = OsRng;
    let mut server_secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut server_secret_bytes);
    let server_secret = StaticSecret::from(server_secret_bytes);
    let server_public = PublicKey::from(&server_secret);
    let server_public_bytes = server_public.to_bytes();
    let server_secret_bytes = server_secret.to_bytes();
    _ = save_server_config(Config { pub_key: encode(server_public_bytes), priv_key: encode(server_secret_bytes) });
}

pub fn generate_shared_key(pub_key: String, private_key: String) -> String {
    let decoded = hex_string_to_u8_array(&pub_key).expect("Decoding failed");
    let client_public = PublicKey::from(decoded);
    let decoded_private = hex_string_to_u8_array(&private_key).expect("Decoding failed");

    let server_private = StaticSecret::from(decoded_private);
    let shared_key = server_private.diffie_hellman(&client_public);
    encode(shared_key.to_bytes())
}

 pub fn decrypt_data(data: String, key: String) -> String{
    let mc = new_magic_crypt!(key, 256);
    let info = mc.decrypt_base64_to_string(&data).unwrap();
    return info;
}

pub fn encrypt_data(data: String, key: String) -> String{
    let mc = new_magic_crypt!(key, 256);
    let base64 = mc.encrypt_str_to_base64(data);
    return base64;
}


pub fn convert_to_outpoint(utxo_str : &String) -> OutPoint{
    let parts : Vec<&str> = utxo_str.split(":").collect();
    let vout : u32 =  parts[1].parse().unwrap();
    let mut byte_arr = hex_string_to_u8_array(parts[0]).unwrap();
    byte_arr.reverse();
    let txid = Txid::from_slice(&byte_arr).expect("Invalid Txid");
    let outpoint = OutPoint{
        txid : txid,
        vout : vout
    };
    outpoint
}

pub fn generate_session_key() -> String {
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let session_key: String = (0..32)
        .map(|_| {
            let mut rng = rand::thread_rng();
            let index = rng.gen_range(0..characters.len());
            characters.chars().nth(index).unwrap()
        })
        .collect();
    return session_key;

}

pub fn read_usermap() -> Result<HashMap<String, String>, String> {
    let target_directory = Path::new("./Json/");
    let user_map_file_path = target_directory.join("user_map.txt");
    match read_from_file(user_map_file_path.to_string_lossy().to_string()) {
        Ok(hash_map_str) => {
            _ = match serde_json::from_str(&hash_map_str) {
                Ok(data) => return Ok(data),
                Err(_) => return Err("Failed to deserialize usermap".to_string()),
            };
        }
        Err(_) => return Err("Could not find usermap".to_string()),
    }
}

pub fn email_lookup(email: &str) -> Result<String, Box<dyn std::error::Error>> {
    if email.contains("@") {
        // Read the user map file and create a HashMap of username-email mappings
        let user_map = match read_usermap() {
            Ok(user_map) => user_map,
            Err(_) => return Err("Unable to get user map".into()),
        };
        // Retrieve the username based on an email
        if let Some(username) = find_key_by_value(&user_map, email.to_lowercase().to_string()) {
            Ok(username.to_string())
        } else {
            Err("Email not found in the user map.".into())
        }
    } else {
        Ok(email.to_string())
    }
}

pub fn save_usermap(usermap: &HashMap<String, String>) -> Result<String, String> {
    let target_directory = Path::new("./Json/");
    let user_map_file_path = target_directory.join("user_map.txt");

    _ = match serde_json::to_string(&usermap) {
        Ok(user_map_string) => write_to_file(user_map_file_path.to_string_lossy().to_string(), user_map_string),
        Err(_) => return Err("Failed to save updated usermap".to_string()),
    };

    Ok("Saved updated user map".to_string())
}

pub fn read_server_config() -> Result<Config, String> {
    let path = format!("./Json/config.txt");
    if !fs::metadata(&path).is_ok() {
        return Err("Unable to read the server config file".to_string());
    }

    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) =>  return Err(err.to_string())
    };

    let parsed_data: Result<Config, _> = serde_json::from_str(&data);
    match parsed_data {
        Ok(data) => return Ok(data),
        Err(_) => return Err("Failed to deserialize contract".to_string())
    }
}

fn save_server_config(config: Config) -> Result<String, String> {
    let path = format!("./Json/config.txt");
    println!("Saving new Config");
    _ = match serde_json::to_string(&config) {
        Ok(config_str) => write_to_file(path, config_str),
        Err(_) => return Err("Failed to saved config".to_string()),
    };

    return Ok("Successfully saved config".to_string());
}

pub fn read_from_file(relative_path: String) -> Result<String,String> {
    if !fs::metadata(&relative_path).is_ok() {
        return Err(String::new());
    }

    _ = match fs::read_to_string(&relative_path) {
        Ok(data) => return Ok(data),
        Err(_) => return Err(String::new()),
    };
}

pub fn write_to_file(relative_path: String, data: String) -> Result<String, String> {
    match fs::write(&relative_path, data) {
        Ok(_) => return Ok(String::new()),
        Err(_) => return Err(String::new()),
    }
}

pub fn hex_string_to_u8_array(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hex_str)?;
    println!("Byte length: {}", bytes.len());
    if bytes.len() == 32 {
        let mut result = [0; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    } else {
        // If the length is not 32, return an error or handle the case accordingly
        Err(hex::FromHexError::InvalidStringLength)
    }
}

fn find_key_by_value(map: &HashMap<String, String>, target_value: String) -> Option<String> {
    for (key, value) in map.clone().iter() {
        if value.to_string() == target_value {
            return Some(key.to_string());
        }
    }
    None
}