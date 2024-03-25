#[macro_use]
extern crate log;

mod circuit;

use circuit::generate_proof;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};
use simple_logger::SimpleLogger;

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let sha = event.payload["event"].get("sha").and_then(|v| v.as_str());
    let input_data = event.payload["event"]
        .get("input_data")
        .and_then(|v| v.as_str());

    match (sha, input_data) {
        (Some(sha_str), Some(input_str)) => match generate_proof(sha_str, input_str) {
            Ok(proof) => Ok(json!({ "proof": proof })),
            Err(e) => {
                error!("Error generating proof: {:?}", e);
                Err(Error::from("Error generating proof"))
            }
        },
        _ => Err(Error::from("Missing SHA or input data")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    SimpleLogger::new().env().init().unwrap();
    lambda_runtime::run(service_fn(handler)).await
}
