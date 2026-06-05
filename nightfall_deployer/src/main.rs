use configuration::{logging::init_logging, settings::Settings};
use log::{error, info, warn};
use nightfall_deployer::deployment::deploy_contracts;

#[tokio::main]
async fn main() {
    // Print banner immediately on startup
    println!(
        r#"
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗        ██╗  ██╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║        ██║  ██║
██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║        ███████║
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║        ╚════██║
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗███████╗██║
╚═╝  ╚═══╝╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝

A Zero-Knowledge Proof (ZKP) based application that enables private transfers of ERC20, ERC721, ERC1155, and ERC3525 tokens on public blockchains, 
leveraging a Layer 2 ZK-ZK rollup architecture to combine scalability with enterprise-grade privacy.
https://github.com/EYBlockchain/nightfall_4_CE
"#
    );
    let settings: Settings = Settings::new().unwrap();
    init_logging(
        settings.nightfall_deployer.log_level.as_str(),
        settings.log_app_only,
    );
    info!("Deployer has started");

    if &settings.signing_key == "set by environment" {
        panic!("Set the deployer signing key in env variable NF4_DEPLOYER_SIGNING_KEY")
    };
    if settings.contracts.deploy_contracts {
        info!("Deploying contracts");
        if let Err(e) = deploy_contracts(&settings).await {
            error!("Deployer failed: {e}");
            std::process::exit(1);
        }
    } else {
        warn!("Skipping contract deployment");
    }
}
