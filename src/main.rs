//! Sentinel GraphQL Security Agent binary (Protocol v2).
//!
//! Run with: `sentinel-agent-graphql-security --config config.yaml`
//!
//! Supports gRPC transport for v2 protocol:
//! - gRPC: `--grpc-address 0.0.0.0:50051` (recommended for v2 features)
//! - UDS: `--socket /tmp/graphql-security.sock` (v1 compatibility mode)

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_agent_graphql_security::{GraphQLSecurityAgent, GraphQLSecurityConfig};
use sentinel_agent_protocol::v2::GrpcAgentServerV2;
use std::path::PathBuf;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// GraphQL Security Agent for Sentinel proxy (Protocol v2).
///
/// This agent analyzes GraphQL queries for security concerns including:
/// - Query depth limiting
/// - Complexity/cost analysis
/// - Alias limiting
/// - Batch query limiting
/// - Introspection control
/// - Field-level authorization
/// - Persisted queries / allowlist mode
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (YAML)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Unix socket path for agent communication (v1 compatibility mode)
    #[arg(short, long, default_value = "/tmp/sentinel-graphql-security.sock")]
    socket: PathBuf,

    /// gRPC address for agent communication (e.g., 0.0.0.0:50051)
    ///
    /// When specified, the agent runs as a gRPC server with full v2 protocol support
    /// including capability negotiation, health reporting, and metrics export.
    #[arg(long)]
    grpc_address: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse().unwrap_or(Level::INFO);
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    info!(
        "Starting Sentinel GraphQL Security Agent v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Protocol version: v2");
    info!("Config file: {}", args.config.display());

    // Load configuration
    let config = if args.config.exists() {
        let content = tokio::fs::read_to_string(&args.config)
            .await
            .context("Failed to read config file")?;
        serde_yaml::from_str(&content).context("Failed to parse config file")?
    } else {
        info!("Config file not found, using defaults");
        GraphQLSecurityConfig::default()
    };

    // Create the agent with async initialization
    let agent = GraphQLSecurityAgent::with_async_init(config)
        .await
        .context("Failed to create agent")?;

    info!("Agent initialized successfully");

    // Run the agent with the appropriate transport
    if let Some(grpc_addr) = args.grpc_address {
        // gRPC transport - full v2 protocol support
        info!("Starting gRPC server on {}", grpc_addr);
        let addr = grpc_addr.parse().context("Invalid gRPC address format")?;

        let server = GrpcAgentServerV2::new("graphql-security", Box::new(agent));

        // Set up graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal");
        };

        tokio::select! {
            result = server.run(addr) => {
                result.context("gRPC server error")?;
            }
            _ = shutdown => {
                info!("Shutting down gRPC server");
            }
        }
    } else {
        // UDS transport - v1 compatibility mode
        // The v1 AgentServer uses the older AgentHandler trait, but we have AgentHandlerV2.
        // For full v2 features, use --grpc-address instead.
        warn!("UDS mode uses v1 protocol. For full v2 features, use --grpc-address");
        info!("Socket path: {}", args.socket.display());

        // Remove existing socket file
        if args.socket.exists() {
            std::fs::remove_file(&args.socket).context("Failed to remove existing socket file")?;
        }

        // Create a v1 UDS server with an adapter
        // Note: We wrap the v2 handler in a v1-compatible adapter
        let adapter = V2ToV1Adapter::new(agent);
        let server = sentinel_agent_protocol::AgentServer::new(
            "graphql-security",
            &args.socket,
            Box::new(adapter),
        );

        // Set up graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal");
        };

        tokio::select! {
            result = server.run() => {
                result.context("UDS server error")?;
            }
            _ = shutdown => {
                info!("Shutting down UDS server");
            }
        }

        // Clean up socket file
        if args.socket.exists() {
            let _ = std::fs::remove_file(&args.socket);
        }
    }

    info!("Agent stopped");
    Ok(())
}

/// Adapter to use a v2 handler with the v1 AgentServer.
///
/// This allows the agent to run in UDS mode for backwards compatibility
/// while still using the v2 handler implementation internally.
struct V2ToV1Adapter {
    handler: GraphQLSecurityAgent,
}

impl V2ToV1Adapter {
    fn new(handler: GraphQLSecurityAgent) -> Self {
        Self { handler }
    }
}

#[async_trait::async_trait]
impl sentinel_agent_protocol::AgentHandler for V2ToV1Adapter {
    async fn on_configure(
        &self,
        event: sentinel_agent_protocol::ConfigureEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        let success = self.handler.on_configure(event.config, None).await;
        if success {
            sentinel_agent_protocol::AgentResponse::default_allow()
        } else {
            sentinel_agent_protocol::AgentResponse {
                version: sentinel_agent_protocol::PROTOCOL_VERSION,
                decision: sentinel_agent_protocol::Decision::Block {
                    status: 500,
                    body: Some("Configuration rejected".to_string()),
                    headers: None,
                },
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: std::collections::HashMap::new(),
                audit: Default::default(),
                needs_more: false,
                request_body_mutation: None,
                response_body_mutation: None,
                websocket_decision: None,
            }
        }
    }

    async fn on_request_headers(
        &self,
        event: sentinel_agent_protocol::RequestHeadersEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        self.handler.on_request_headers(event).await
    }

    async fn on_request_body_chunk(
        &self,
        event: sentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        self.handler.on_request_body_chunk(event).await
    }

    async fn on_response_headers(
        &self,
        event: sentinel_agent_protocol::ResponseHeadersEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        self.handler.on_response_headers(event).await
    }

    async fn on_response_body_chunk(
        &self,
        event: sentinel_agent_protocol::ResponseBodyChunkEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        self.handler.on_response_body_chunk(event).await
    }

    async fn on_request_complete(
        &self,
        event: sentinel_agent_protocol::RequestCompleteEvent,
    ) -> sentinel_agent_protocol::AgentResponse {
        use sentinel_agent_protocol::v2::AgentHandlerV2;
        self.handler.on_request_complete(event).await
    }
}
