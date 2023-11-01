use authorize_service::*;

use structopt::StructOpt;
use warp::Filter;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(short, long, default_value = "3030")]
    port: u16,
}

async fn run(port: u16) {
    pretty_env_logger::init();

    let routes = keygen().or(authorize()).with(warp::trace(
        |info| tracing::debug_span!("Debugging headers", headers = ?info.request_headers()),
    ));

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    run(opt.port).await;
}
