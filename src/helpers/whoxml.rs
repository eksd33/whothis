use crate::helpers::configuration::*;

#[derive(serde::Deserialize, Debug)]
pub struct WhoXml{
    pub who_xml: String,
}



pub async fn who_xml_get (host: String, api_conf: ApiConfig )-> Result<(), Box<dyn std::error::Error>>{
    let mut url = ApiConfig::get_whois_url(&api_conf);
    url.push_str(host.as_str());

    let who_xml_resp = reqwest::get(url)
        .await?
        .json::<WhoXml>()
        .await?;
    Ok(())
}


