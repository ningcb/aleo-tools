#[macro_use]
extern crate criterion;

use criterion::{BatchSize, Criterion};
use snarkvm::circuit::AleoV0;
use snarkvm::prelude::{Address, Literal, PrivateKey, Process, Value, U64};
use std::str::FromStr;

use authorize_service::{
    authorize_transfer_public, private_key_from_seed, AuthorizeRequest, CurrentNetwork,
};

fn bench_private_key_from_seed(c: &mut Criterion) {
    c.bench_function("private_key_from_seed", |b| {
        b.iter(|| private_key_from_seed::<CurrentNetwork>("94030298402398402"))
    });
}

fn bench_authorize_transfer_public(c: &mut Criterion) {
    let request = AuthorizeRequest {
        private_key: PrivateKey::from_str(
            "APrivateKey1zkpCE9rCw9SixY82xaDrW2Hwxc2f3VjeuR2oZHR81zcuUDV",
        )
        .unwrap(),
        recipient: Address::from_str(
            "aleo1zcsyu7wfrdp4n6gq752p3np45sat9d6zun2uhjer2h4skccsgsgq7ndrnj",
        )
        .unwrap(),
        amount_in_microcredits: U64::new(100),
        priority_fee_in_microcredits: U64::new(0),
    };
    c.bench_function("authorize_transfer_public", |b| {
        b.iter_batched(
            || request.clone(),
            |request| authorize_transfer_public::<CurrentNetwork>(request).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_authorize(c: &mut Criterion) {
    let process = Process::<CurrentNetwork>::load().unwrap();
    let private_key =
        PrivateKey::from_str("APrivateKey1zkpCE9rCw9SixY82xaDrW2Hwxc2f3VjeuR2oZHR81zcuUDV")
            .unwrap();
    let program_id = "credits.aleo";
    let function_name = "transfer_public";
    let inputs = vec![
        Value::<CurrentNetwork>::from(Literal::Address(
            Address::from_str("aleo1zcsyu7wfrdp4n6gq752p3np45sat9d6zun2uhjer2h4skccsgsgq7ndrnj")
                .unwrap(),
        )),
        Value::from(Literal::U64(U64::new(100))),
    ];
    let rng = &mut rand::thread_rng();

    c.bench_function("general_authorize", move |b| {
        b.iter_batched(
            || inputs.clone(),
            |inputs| {
                process
                    .authorize::<AleoV0, _>(
                        &private_key,
                        program_id,
                        function_name,
                        inputs.iter(),
                        rng,
                    )
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = routes;
    config = Criterion::default();
    targets = bench_private_key_from_seed, bench_authorize_transfer_public, bench_authorize
}
criterion_main!(routes);
