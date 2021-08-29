#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

mod helpers;

use crate::helpers::configuration::*;
use crate::helpers::request_handling::*;
use crate::helpers::virustotal::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    let load_config = get_conf().expect("erro loading config file");
    let virustotal_api_key = load_config.virustotal_api_key;
    let src_type = String::from("ip");

    let vt_ip_result = get_virustotal(String::from("8.8.8.8"),virustotal_api_key, src_type).await?;
    println!("{:?}", vt_ip_result);
    Ok(())    
}
