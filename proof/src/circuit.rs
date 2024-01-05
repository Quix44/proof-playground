use bellman::groth16::{create_random_proof, generate_random_parameters};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sha2::{Digest, Sha256};
use bls12_381::Bls12;
use num_bigint::{BigInt, Sign};
use bls12_381::{Scalar};
use std::convert::TryInto;
use num_traits::Num;
use rand::rngs::OsRng;

const BLS12_381_SCALAR_FIELD_ORDER: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184512";

fn sha256_to_scalar(data: &[u8]) -> Result<Scalar, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let hash_bigint = BigInt::from_bytes_be(Sign::Plus, &hash);
    let prime_order = BigInt::from_str_radix(BLS12_381_SCALAR_FIELD_ORDER, 10).unwrap();
    let scalar_value = hash_bigint % prime_order;

    let scalar_bytes: [u8; 32] = scalar_value.to_bytes_be().1
        .try_into()
        .unwrap_or_else(|_| [0u8; 32]);

    let scalar_ctoption = Scalar::from_bytes(&scalar_bytes);
    if scalar_ctoption.is_some().unwrap_u8() == 1 {
        info!("Successfully converted to Scalar");
        Ok(scalar_ctoption.unwrap())
    } else {
        info!("Failed to convert to Scalar");
        Err("Failed to convert to scalar")
    }
}

pub struct EmitlyCircuit {
    docker_sha_num: Scalar,
    json_input_num: Scalar,
    expected_sum: Scalar,
}

// Circuit implementation
impl Circuit<Scalar> for EmitlyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let docker_sha_var = cs.alloc(|| "docker sha", || Ok(self.docker_sha_num))?;
        let json_input_var = cs.alloc(|| "json input", || Ok(self.json_input_num))?;
        let expected_sum_var = cs.alloc(|| "expected sum", || Ok(self.expected_sum))?;

        // Temporary variable for the sum
        let sum = cs.alloc(
            || "sum",
            || {
                let mut tmp = self.docker_sha_num;
                tmp += &self.json_input_num;
                Ok(tmp)
            },
        )?;

        // Enforce docker_sha_num + json_input_num = sum
        cs.enforce(
            || "sum constraint",
            |lc| lc + docker_sha_var + json_input_var,
            |lc| lc + CS::one(),
            |lc| lc + sum,
        );

        // Enforce sum = expected_sum
        cs.enforce(
            || "expected sum constraint",
            |lc| lc + sum,
            |lc| lc + CS::one(),
            |lc| lc + expected_sum_var,
        );

        Ok(())
    }
}

// Generate zk-SNARK proof
pub fn generate_proof(docker_sha: &str, json_input: &str) -> Result<String, String> {
    let docker_sha_num = sha256_to_scalar(docker_sha.as_bytes())
        .map_err(|e| e.to_string())?;
    let json_input_num = sha256_to_scalar(json_input.as_bytes())
        .map_err(|e| e.to_string())?;

    let expected_sum = docker_sha_num + json_input_num;

    let circuit_for_params = EmitlyCircuit {
        docker_sha_num,
        json_input_num,
        expected_sum,
    };

    let mut rng = OsRng;

    let params = generate_random_parameters::<Bls12, _, _>(circuit_for_params, &mut rng)
        .map_err(|e| format!("Error generating random parameters: {}", e))?;

    // Recreate the circuit for the proof
    let circuit_for_proof = EmitlyCircuit {
        docker_sha_num,
        json_input_num,
        expected_sum,
    };

    let proof = create_random_proof(circuit_for_proof, &params, &mut rng)
        .map_err(|e| format!("Error creating random proof: {}", e))?;

    Ok(format!("{:?}", proof))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_scalar_with_regular_sha_string() {
        let input = "aea7a9e96d97f78c076939c22abcb171d624f1b9c41de4dc14611f4f01506950";
        let result = sha256_to_scalar(input.as_bytes());
        println!("Result for regular string: {:?}", result);
    }

    #[test]
    fn test_string_to_scalar_with_txn_hash_string() {
        let input = "0xf94c20fbc81d4feb8c21a0c9dad46994fa65e7d0c6341aa8dcf95ba38b970e20";
        let result = sha256_to_scalar(input.as_bytes());
        println!("Result for TXN string: {:?}", result);
    }

    #[test]
    fn test_generate_proof() {
        let docker_sha = "aea7a9e96d97f78c076939c22abcb171d624f1b9c41de4dc14611f4f01506950";
        let json_input = "0xf94c20fbc81d4feb8c21a0c9dad46994fa65e7d0c6341aa8dcf95ba38b970e20";

        match generate_proof(docker_sha, json_input) {
            Ok(proof) => {
                assert!(!proof.is_empty(), "Proof should not be empty");
                println!("Generated proof: {}", proof);
            },
            Err(e) => panic!("Failed to generate proof: {}", e),
        }
    }
}