pub mod benchmarks;
pub mod cbor;
pub mod crypto;
pub mod fault_matrix;
pub mod oracles;
pub mod p2p_quic;
pub mod plane1_eval;
pub mod plane2_store;
pub mod plane3_secrets;
pub mod plane4_state;
pub mod schema;
pub mod tracy_prof;
pub mod watchdog_boot;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
