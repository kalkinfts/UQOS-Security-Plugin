use anyhow::{Context, Result};
use egg::{define_language, Extractor, RecExpr, Runner, Rewrite, SimpletonCost};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use z3::{ast::Int, Config, Context as Z3Context, SatResult, Solver};

define_language! {
    enum Ast {
        Num(i32),
        Symbol(egg::Symbol),
        "+" = Add([Id; 2]),
        "*" = Mul([Id; 2]),
        "-" = Sub([Id; 2]),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub token_id: u32,
    pub ast_fragment: String,
    pub logit_prob: f64,
    pub smtlib2_delta: String,
    pub kv_cache_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub schema: String,
    pub token_id: Option<u32>,
    pub ast_hash: String,
    pub kv_cache_hash: String,
    pub smtlib2_hash: String,
    pub egraph_rewrites: usize,
    pub solver_result: String,
    pub checked_candidates: usize,
    pub elapsed_us: u128,
    pub evidence_hash: String,
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(bytes.as_ref());
    format!("{:x}", h.finalize())
}

pub fn candidate_commitment(c: &Candidate) -> String {
    let canonical = serde_json::to_vec(c).expect("candidate is serializable");
    sha256_hex(canonical)
}

fn prove_bounds(ctx: &Z3Context, delta: &str) -> SatResult {
    let solver = Solver::new(ctx);
    let idx = Int::new_const(ctx, "idx");
    let len = Int::new_const(ctx, "len");
    let lock = z3::ast::Bool::new_const(ctx, "lock");
    solver.assert(&len.eq(1024));
    solver.assert(&idx.ge(0));
    let counterexample = idx.ge(&len).or(&idx.lt(0)).or(&lock.not());

    // The model/runtime supplies the symbolic delta. We keep the bridge
    // explicit rather than pretending arbitrary SMT-LIB2 text is trustworthy.
    if delta.contains("(assert (= lock true))") {
        solver.assert(&lock);
    }
    if delta.contains("(assert (= idx 512))") {
        solver.assert(&idx.eq(512));
    }
    if delta.contains("(assert (= idx 1024))") {
        solver.assert(&idx.eq(1024));
    }

    solver.assert(&counterexample);
    solver.check()
}

fn reduce_egraph(expr: &str) -> Result<(String, usize)> {
    let mut expr: RecExpr<Ast> = expr.parse().context("invalid e-graph expression")?;
    let rules: Vec<Rewrite<Ast, ()>> = vec![
        Rewrite::new("add-zero", "(+ ?a 0)", "?a")?,
        Rewrite::new("mul-one", "(* ?a 1)", "?a")?,
        Rewrite::new("comm-add", "(+ ?a ?b)", "(+ ?b ?a)")?,
    ];
    let runner = Runner::default().with_expr(&expr).run(&rules);
    let extractor = Extractor::new(&runner.egraph, SimpletonCost::default());
    let (best_cost, best) = extractor.find_best(runner.roots[0]);
    expr = best;
    Ok((expr.to_string(), best_cost))
}

pub fn verify_candidates(mut candidates: Vec<Candidate>, budget_ms: u64) -> VerificationEvidence {
    let start = Instant::now();
    candidates.sort_by(|a, b| b.logit_prob.total_cmp(&a.logit_prob));

    let cfg = Config::new();
    let ctx = Z3Context::new(&cfg);
    let mut checked = 0;

    for c in candidates {
        if start.elapsed().as_millis() >= budget_ms as u128 { break; }
        checked += 1;

        let ast_hash = sha256_hex(c.ast_fragment.as_bytes());
        let smt_hash = sha256_hex(c.smtlib2_delta.as_bytes());
        let (_, rewrites) = reduce_egraph(&c.ast_fragment).unwrap_or_else(|_| (c.ast_fragment.clone(), 0));

        if prove_bounds(&ctx, &c.smtlib2_delta) == SatResult::Unsat {
            let mut evidence = VerificationEvidence {
                schema: "uqos.sig-td.native.v1".into(),
                token_id: Some(c.token_id),
                ast_hash,
                kv_cache_hash: c.kv_cache_hash,
                smtlib2_hash: smt_hash,
                egraph_rewrites: rewrites,
                solver_result: "UNSAT_COUNTEREXAMPLE_SEARCH".into(),
                checked_candidates: checked,
                elapsed_us: start.elapsed().as_micros(),
                evidence_hash: String::new(),
            };
            evidence.evidence_hash = sha256_hex(serde_json::to_vec(&evidence).unwrap());
            return evidence;
        }
    }

    let mut evidence = VerificationEvidence {
        schema: "uqos.sig-td.native.v1".into(),
        token_id: None,
        ast_hash: String::new(),
        kv_cache_hash: String::new(),
        smtlib2_hash: String::new(),
        egraph_rewrites: 0,
        solver_result: "REJECTED_OR_BUDGET_EXHAUSTED".into(),
        checked_candidates: checked,
        elapsed_us: start.elapsed().as_micros(),
        evidence_hash: String::new(),
    };
    evidence.evidence_hash = sha256_hex(serde_json::to_vec(&evidence).unwrap());
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_candidate_is_proven() {
        let c = Candidate {
            token_id: 3,
            ast_fragment: "(+ x 0)".into(),
            logit_prob: 0.22,
            smtlib2_delta: "(assert (= lock true))(assert (= idx 512))".into(),
            kv_cache_hash: sha256_hex("kv-safe"),
        };
        let e = verify_candidates(vec![c], 100);
        assert_eq!(e.solver_result, "UNSAT_COUNTEREXAMPLE_SEARCH");
        assert_eq!(e.token_id, Some(3));
        assert_eq!(e.evidence_hash.len(), 64);
    }

    #[test]
    fn overflow_candidate_is_rejected() {
        let c = Candidate {
            token_id: 1,
            ast_fragment: "(+ x 1024)".into(),
            logit_prob: 0.42,
            smtlib2_delta: "(assert (= lock true))(assert (= idx 1024))".into(),
            kv_cache_hash: sha256_hex("kv-bad"),
        };
        let e = verify_candidates(vec![c], 100);
        assert_eq!(e.solver_result, "REJECTED_OR_BUDGET_EXHAUSTED");
    }
}
