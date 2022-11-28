use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use bbs_issue_212::{prf_in_loop, expand_message_in_loop, expand_message_and_prf_in_loop};
use std::time::Duration;

const U_VALUES: [usize; 5] = [100, 1000, 2000, 3000, 4000];

pub fn prf_in_loop_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("PRF_in_a_loop");
    for count in U_VALUES.iter() {
        group.bench_with_input(
            BenchmarkId::new("U", count),
            count,
            |b, &count| {
                b.iter(|| prf_in_loop(black_box(count)));
            }
        );
    }

    group.finish();
}

pub fn expand_message_in_loop_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Expand_message_in_a_loop");

    for count in U_VALUES.iter() {
        group.bench_with_input(
            BenchmarkId::new("U", count),
            count,
            |b, &count| {
                b.iter(|| expand_message_in_loop(black_box(count)));
            });
    }

    group.finish();
}

pub fn expand_message_and_prf_in_loop_benchmark(c: &mut Criterion) {

    let mut group = c.benchmark_group("Expand_message_and_PRF_in_a_loop");

    for count in U_VALUES.iter() {
        group.bench_with_input(
            BenchmarkId::new("U", count),
            count,
            |b, &count| {
                b.iter(|| expand_message_and_prf_in_loop(black_box(count)));
            });
    }

    group.finish();
}

criterion_group!(
    name = sha256_based_bences;
    config = Criterion::default().measurement_time(Duration::from_secs(32));
    targets  = prf_in_loop_benchmark,
               expand_message_in_loop_benchmark,
               expand_message_and_prf_in_loop_benchmark
);
criterion_main!(sha256_based_bences);
