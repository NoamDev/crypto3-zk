//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef RUN_BACS_PPZKSNARK_HPP_
#define RUN_BACS_PPZKSNARK_HPP_

#include <nil/algebra/curves/public_params.hpp>

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/examples/bacs_examples.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * BACS example (specified by a circuit, primary input, and auxiliary input).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example, const bool test_serialization);

                /**
                 * The code below provides an example of all stages of running a BACS ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     circuit C to create a proving and a verification key for C.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for C, and an auxiliary input for C.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for C, and a proof.
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example, const bool test_serialization) {
                    algebra::enter_block("Call to run_bacs_ppzksnark");

                    algebra::print_header("BACS ppzkSNARK Generator");
                    bacs_ppzksnark_keypair<CurveType> keypair = bacs_ppzksnark_generator<CurveType>(example.circuit);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after generator");

                    algebra::print_header("Preprocess verification key");
                    bacs_ppzksnark_processed_verification_key<CurveType> pvk =
                        bacs_ppzksnark_verifier_process_vk<CurveType>(keypair.vk);

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of keys");
                        keypair.pk = algebra::reserialize<bacs_ppzksnark_proving_key<CurveType>>(keypair.pk);
                        keypair.vk = algebra::reserialize<bacs_ppzksnark_verification_key<CurveType>>(keypair.vk);
                        pvk = algebra::reserialize<bacs_ppzksnark_processed_verification_key<CurveType>>(pvk);
                        algebra::leave_block("Test serialization of keys");
                    }

                    algebra::print_header("BACS ppzkSNARK Prover");
                    bacs_ppzksnark_proof<CurveType> proof =
                        bacs_ppzksnark_prover<CurveType>(keypair.pk, example.primary_input, example.auxiliary_input);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after prover");

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of proof");
                        proof = algebra::reserialize<bacs_ppzksnark_proof<CurveType>>(proof);
                        algebra::leave_block("Test serialization of proof");
                    }

                    algebra::print_header("BACS ppzkSNARK Verifier");
                    bool ans = bacs_ppzksnark_verifier_strong_IC<CurveType>(keypair.vk, example.primary_input, proof);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after verifier");
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    algebra::print_header("BACS ppzkSNARK Online Verifier");
                    bool ans2 = bacs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, example.primary_input, proof);
                    assert(ans == ans2);

                    algebra::leave_block("Call to run_bacs_ppzksnark");

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RUN_BACS_PPZKSNARK_HPP_
