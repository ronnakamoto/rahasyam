use crate::proving::nova_v1::step_circuit::nova_step_circuit::RollupStepCircuit;
use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable},
    provider::Bn256EngineKZG,
    traits::{circuit::StepCircuit, Engine},
};
use serde_json::{json, Value};

type E1 = Bn256EngineKZG;
type F1 = <E1 as Engine>::Scalar;

/// A sparse matrix entry: (constraint_index, variable_index, coefficient).
/// Coefficients are stored as hex strings for JSON portability.
#[derive(Debug, Clone)]
pub struct SparseEntry {
    pub constraint: usize,
    pub variable: usize,
    pub coeff_hex: String,
}

/// Captured R1CS shape in sparse matrix form.
///
/// The Nova/bellpepper constraint system enforces `A * B = C` where
/// `A`, `B`, `C` are linear combinations over all variables (inputs +
/// auxiliaries).  We flatten variables to a single 0-based index:
/// inputs come first, then auxiliaries.
#[derive(Debug, Clone)]
pub struct R1CSShape {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_constraints: usize,
    pub a: Vec<SparseEntry>,
    pub b: Vec<SparseEntry>,
    pub c: Vec<SparseEntry>,
    pub constraint_names: Vec<String>,
}

impl R1CSShape {
    /// Serialize the shape to a JSON [`Value`].
    pub fn to_json(&self) -> Value {
        let mk_matrix = |entries: &[SparseEntry]| {
            entries
                .iter()
                .map(|e| {
                    json!({
                        "i": e.constraint,
                        "j": e.variable,
                        "v": e.coeff_hex,
                    })
                })
                .collect::<Vec<_>>()
        };
        json!({
            "num_inputs": self.num_inputs,
            "num_aux": self.num_aux,
            "num_variables": self.num_inputs + self.num_aux,
            "num_constraints": self.num_constraints,
            "a": mk_matrix(&self.a),
            "b": mk_matrix(&self.b),
            "c": mk_matrix(&self.c),
            "constraint_names": self.constraint_names,
        })
    }

    /// Serialize to a pretty-printed JSON string.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string_pretty(&self.to_json()).expect("JSON serialization")
    }
}

/// A [`ConstraintSystem`] implementation whose sole purpose is to
/// capture the R1CS matrices (A, B, C) emitted by a circuit.
///
/// After `synthesize` finishes, call `.into_shape()` to obtain the
/// [`R1CSShape`].
pub struct R1CSExporter<Scalar: PrimeField> {
    num_inputs: usize,
    num_aux: usize,
    constraints: Vec<(
        LinearCombination<Scalar>,
        LinearCombination<Scalar>,
        LinearCombination<Scalar>,
        String,
    )>,
}

impl<Scalar: PrimeField> R1CSExporter<Scalar> {
    pub fn new() -> Self {
        Self {
            num_inputs: 1, // ONE is always input 0
            num_aux: 0,
            constraints: vec![],
        }
    }

    /// Consume the exporter and return the captured [`R1CSShape`].
    pub fn into_shape(self) -> R1CSShape {
        let var_index = |v: &Variable| match v.0 {
            Index::Input(i) => i,
            Index::Aux(i) => self.num_inputs + i,
        };

        let flatten_lc =
            |lc: &LinearCombination<Scalar>, constraint_idx: usize, out: &mut Vec<SparseEntry>| {
                for (var, coeff) in lc.iter() {
                    let coeff_bytes = coeff.to_repr();
                    out.push(SparseEntry {
                        constraint: constraint_idx,
                        variable: var_index(&var),
                        coeff_hex: hex::encode(coeff_bytes.as_ref()),
                    });
                }
            };

        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = Vec::new();
        let mut names = Vec::new();

        for (i, (lc_a, lc_b, lc_c, name)) in self.constraints.iter().enumerate() {
            flatten_lc(lc_a, i, &mut a);
            flatten_lc(lc_b, i, &mut b);
            flatten_lc(lc_c, i, &mut c);
            names.push(name.clone());
        }

        R1CSShape {
            num_inputs: self.num_inputs,
            num_aux: self.num_aux,
            num_constraints: self.constraints.len(),
            a,
            b,
            c,
            constraint_names: names,
        }
    }
}

impl<Scalar: PrimeField> Default for R1CSExporter<Scalar> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Scalar: PrimeField> ConstraintSystem<Scalar> for R1CSExporter<Scalar> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, _f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.num_aux;
        self.num_aux += 1;
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(&mut self, _annotation: A, _f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.num_inputs;
        self.num_inputs += 1;
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let name = annotation().into();
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());
        self.constraints.push((a, b, c, name));
    }

    fn push_namespace<NR, N>(&mut self, _name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

/// Drive the padding [`RollupStepCircuit`] through [`R1CSExporter`] and
/// return the captured shape.
///
/// Because the circuit uses uniform R1CS shape (padding and real steps
/// allocate identically), the shape produced from a padding circuit is
/// identical to the shape of a real step.
pub fn export_rollup_step_r1cs() -> R1CSShape {
    let circuit = RollupStepCircuit::<F1>::padding();
    let z0 =
        vec![F1::ZERO; crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLOUP_ARITY];
    let mut exporter = R1CSExporter::<F1>::new();
    // Allocate input variables for the IVC state z so they are
    // classified as public inputs in the exported R1CS matrices.
    let z_allocated: Vec<_> = z0
        .iter()
        .enumerate()
        .map(|(i, v)| {
            nova_snark::frontend::num::AllocatedNum::alloc_input(
                exporter.namespace(|| format!("z_in_{i}")),
                || Ok(*v),
            )
            .expect("alloc_input never fails in R1CSExporter")
        })
        .collect();
    let _ = StepCircuit::synthesize(&circuit, &mut exporter, &z_allocated);
    exporter.into_shape()
}

/// Convenience: export the R1CS shape to a JSON string.
pub fn export_rollup_step_r1cs_json() -> String {
    export_rollup_step_r1cs().to_json_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r1cs_export_produces_non_trivial_shape() {
        let shape = export_rollup_step_r1cs();
        assert!(shape.num_constraints > 0, "circuit must emit constraints");
        assert_eq!(
            shape.num_inputs,
            1 + crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLOUP_ARITY,
            "inputs = ONE + arity state variables"
        );
        // Print summary for human inspection
        println!("R1CS Export Summary:");
        println!("  inputs:      {}", shape.num_inputs);
        println!("  aux:         {}", shape.num_aux);
        println!("  constraints: {}", shape.num_constraints);
    }

    #[test]
    fn r1cs_export_json_roundtrips() {
        let shape = export_rollup_step_r1cs();
        let json_str = shape.to_json_string();
        let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert_eq!(
            parsed["num_constraints"].as_u64().unwrap() as usize,
            shape.num_constraints
        );
    }
}
