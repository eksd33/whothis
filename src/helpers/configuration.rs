pub fn get_conf() -> Result<ApiConfig, config::ConfigError>{
    let mut file_path = dirs::config_dir().expect("Error locating config folder");
    file_path.push("whothis_config.yaml");
    let mut default_conf = config::Config::default();
    
    match default_conf.merge(config::File::from(file_path)){
        Ok(conf) => conf.clone().try_into(),
        Err(why) => Err(why),
    }
}
#[derive(serde::Deserialize, Debug)]
pub struct ApiConfig{
    pub who_xml_api_key: String,
    pub virustotal_api_key: String,
    pub hybrid_analysis: String,
}

impl ApiConfig{
    pub fn get_whois_url(&self) -> String {
        format!("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={}&domainName=", self.who_xml_api_key)
        }
    pub fn get_virustotal_api_key(&self) -> String {
        self.virustotal_api_key.clone()
        }
}
