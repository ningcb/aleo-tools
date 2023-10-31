use super::*;

use async_trait::async_trait;

use snarkvm::ledger::query::QueryTrait;
use snarkvm::prelude::Field;

#[derive(Clone, Debug)]
pub struct StaticQuery<N: Network> {
    state_root: Option<N::StateRoot>,
    state_path: Option<StatePath<N>>,
}

#[async_trait(?Send)]
impl<N: Network> QueryTrait<N> for StaticQuery<N> {
    fn current_state_root(&self) -> Result<N::StateRoot> {
        self.state_root
            .ok_or_else(|| anyhow!("State root is not set."))
    }

    async fn current_state_root_async(&self) -> Result<N::StateRoot> {
        self.state_root
            .ok_or_else(|| anyhow!("State root is not set."))
    }

    fn get_state_path_for_commitment(&self, _: &Field<N>) -> Result<StatePath<N>> {
        self.state_path
            .clone()
            .ok_or_else(|| anyhow!("State path is not set."))
    }

    async fn get_state_path_for_commitment_async(&self, _: &Field<N>) -> Result<StatePath<N>> {
        self.state_path
            .clone()
            .ok_or_else(|| anyhow!("State path is not set."))
    }
}
