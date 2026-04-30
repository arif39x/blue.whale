use clap::Parser;
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixListener;
use std::io::{Read, Write};
use std::path::Path;
use reqwest::Client;
use std::sync::Arc;
use futures::future::join_all;
use tokio::time::{timeout, Duration};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    socket: String,

    #[arg(short, long, default_value = "http://localhost:11434")]
    ollama_url: String,

    #[arg(short, long, default_value = "mannix/llama3.1-8b-abliterated:latest")]
    models: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BrainMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    context: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BrainResponse {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    results: Vec<String>,
    #[serde(default)]
    analysis: String,
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

struct ModelPool {
    client: Client,
    ollama_url: String,
    models: Vec<String>,
}

impl ModelPool {
    fn new(ollama_url: String, models: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            ollama_url,
            models,
        }
    }

    async fn generate(&self, prompt: &str) -> Vec<String> {
        let mut futures = Vec::new();

        for model in &self.models {
            let client = self.client.clone();
            let url = format!("{}/api/generate", self.ollama_url);
            let req = OllamaRequest {
                model: model.clone(),
                prompt: prompt.to_string(),
                stream: false,
            };

            futures.push(tokio::spawn(async move {
                let res = timeout(Duration::from_secs(15), client.post(url).json(&req).send()).await;
                match res {
                    Ok(Ok(resp)) => {
                        let ollama_res: OllamaResponse = resp.json().await.unwrap_or(OllamaResponse { response: "".to_string() });
                        ollama_res.response.lines()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<String>>()
                    }
                    _ => vec![],
                }
            }));
        }

        let results = join_all(futures).await;
        results.into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect()
    }

    async fn analyze(&self, prompt: &str) -> String {

        if self.models.is_empty() { return "No models available".to_string(); }

        let model = &self.models[0];
        let req = OllamaRequest {
            model: model.clone(),
            prompt: prompt.to_string(),
            stream: false,
        };

        let res = timeout(Duration::from_secs(20), self.client.post(format!("{}/api/generate", self.ollama_url))
            .json(&req)
            .send()).await;

        match res {
            Ok(Ok(resp)) => {
                let ollama_res: OllamaResponse = resp.json().await.unwrap_or(OllamaResponse { response: "Analysis failed".to_string() });
                ollama_res.response
            }
            _ => "Analysis timed out".to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();

    if args.models.is_empty() {
        args.models = vec![
            "mannix/llama3.1-8b-abliterated:latest".to_string(),
            "huihui_ai/qwen2.5-abliterate:7b-instruct".to_string(),
            "dolphin3:latest".to_string(),
        ];
    }

    let pool = Arc::new(ModelPool::new(args.ollama_url.clone(), args.models.clone()));

    if Path::new(&args.socket).exists() {
        std::fs::remove_file(&args.socket)?;
    }

    let listener = UnixListener::bind(&args.socket)?;
    println!("[brain-rust] Listening on {} with {} models", args.socket, args.models.len());

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let pool_clone = pool.clone();

                tokio::spawn(async move {
                    let mut buffer = [0; 8192];
                    loop {
                        let n = match stream.read(&mut buffer) {
                            Ok(n) if n > 0 => n,
                            _ => break,
                        };

                        let msg: BrainMessage = match rmp_serde::from_slice(&buffer[..n]) {
                            Ok(m) => m,
                            Err(_) => break,
                        };

                        let response = handle_message(pool_clone.clone(), msg).await;
                        let packed = rmp_serde::to_vec(&response).unwrap();
                        let _ = stream.write_all(&packed);
                    }
                });
            }
            Err(err) => {
                eprintln!("[brain-rust] Connection failed: {}", err);
            }
        }
    }

    Ok(())
}

async fn handle_message(pool: Arc<ModelPool>, msg: BrainMessage) -> BrainResponse {
    match msg.msg_type.as_str() {
        "mutate" => {
            let prompt = format!(
                "Act as an advanced security researcher. Generate 3 unique, high-bypass polymorphic mutations for the following {} payload targeting a {} context: '{}'. Return ONLY the mutations, one per line, no explanation.",
                msg.category, msg.context, msg.payload
            );

            let results = pool.generate(&prompt).await;
            BrainResponse {
                msg_type: "mutation_results".to_string(),
                results,
                analysis: "".to_string()
            }
        }
        "analyze" => {
            let prompt = format!(
                "Analyze this potential vulnerability evidence and explain why it is or isn't a true positive: '{}' in category {}.",
                msg.payload, msg.category
            );

            let analysis = pool.analyze(&prompt).await;
            BrainResponse {
                msg_type: "analysis_results".to_string(),
                results: vec![],
                analysis
            }
        }
        _ => BrainResponse {
            msg_type: "error".to_string(),
            results: vec![],
            analysis: "Unknown message type".to_string()
        },
    }
}
