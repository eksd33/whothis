use crate::helpers::configuration::*;

#[derive (serde::Deserialize, Debug)]
pub enum Virustotal {
    DataIp(VTdataIp),
    DataUrl(VTdataUrl),
}

#[derive(serde::Deserialize, Debug)]
pub struct VTdataIp {
    data: Vec<VTattributesIp>,
}

#[derive(serde::Deserialize, Debug)]
pub struct VTattributesIp {
    attributes: VTvaluesIp,
}

#[derive(serde::Deserialize, Debug)]
pub struct VTvaluesIp {
    as_owner: String,
    asn: i32,
    country: String,
    last_analysis_stats: VTanalysisResult,
    reputation: i32,
}

#[derive(serde::Deserialize, Debug)]
pub struct VTanalysisResult {
    harmless: i8 ,
    malicious: i8,
    suspicious: i8,
    undetected: i8,
    timeout: i8,
}

#[derive(serde::Deserialize, Debug)]
pub struct VTdataUrl {
    data:  Vec<VTattributesUrl>,
}

#[derive (serde::Deserialize, Debug)]
pub struct VTattributesUrl {
    attributes: VTvaluesUrl,
}

#[derive (serde::Deserialize, Debug)]
pub struct VTvaluesUrl {
    last_analysis_stats: VTanalysisResultUrl,
    times_submitted: i16,
    reputation: i16,
    total_votes: VTvotesUrl,

}
#[derive(serde::Deserialize, Debug)]
pub struct VTanalysisResultUrl {
    harmless: i8 ,
    malicious: i8,
    suspicious: i8,
    undetected: i8,
    timeout: i8,
}
#[derive (serde::Deserialize, Debug)]
pub struct VTvotesUrl {
    harmless: i8,
    malicious: i8, 
}

pub async fn get_virustotal (src: String, api_key: String, src_type: String) -> Result<Virustotal, Box<dyn std::error::Error>>{
    
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/search?query={}", src);

    let resp = client
        .get(url)
        .header("x-apikey", &api_key)
        .send()
        .await?
        .text()
        .await?;
    if src_type.eq("ip"){
        let de_vt_ip: VTdataIp = serde_json::from_str(resp.as_str()).expect("error deserializing");
        return Ok(Virustotal::DataIp(de_vt_ip));
    }else{
        let de_vt_url: VTdataUrl = serde_json::from_str(resp.as_str()).expect("error deserializing");
        return Ok(Virustotal::DataUrl(de_vt_url));
    }
}

