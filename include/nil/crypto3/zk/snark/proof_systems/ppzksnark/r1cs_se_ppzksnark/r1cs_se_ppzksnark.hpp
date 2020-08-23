//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a SEppzkSNARK for R1CS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm (with strong or weak input consistency)
// - online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates (a modification of) the protocol of \[GM17],
// by following extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - SEppzkSNARK = "Simulation-Extractable PreProcessing Zero-Knowledge Succinct
//     Non-interactive ARgument of Knowledge"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef R1CS_SE_PPZKSNARK_HPP_
#define R1CS_SE_PPZKSNARK_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/detail/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark_params.hpp>

#include <nil/algebra/scalar_multiplication/multiexp.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap/r1cs_to_sap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                template<typename CurveType>
                class r1cs_se_ppzksnark_proving_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_proving_key<CurveType> &pk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_proving_key<CurveType> &pk);

                /**
                 * A proving key for the R1CS SEppzkSNARK.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_proving_key {
                public:
                    // G^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    algebra::G1_vector<CurveType> A_query;

                    // H^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    algebra::G2_vector<CurveType> B_query;

                    // G^{gamma^2 * C_i(t) + (alpha + beta) * gamma * A_i(t)}
                    // for sap.num_inputs() + 1 < i <= sap.num_variables()
                    algebra::G1_vector<CurveType> C_query_1;

                    // G^{2 * gamma^2 * Z(t) * A_i(t)} for 0 <= i <= sap.num_variables()
                    algebra::G1_vector<CurveType> C_query_2;

                    // G^{gamma * Z(t)}
                    algebra::G1<CurveType> G_gamma_Z;

                    // H^{gamma * Z(t)}
                    algebra::G2<CurveType> H_gamma_Z;

                    // G^{(alpha + beta) * gamma * Z(t)}
                    algebra::G1<CurveType> G_ab_gamma_Z;

                    // G^{gamma^2 * Z(t)^2}
                    algebra::G1<CurveType> G_gamma2_Z2;

                    // G^{gamma^2 * Z(t) * t^i} for 0 <= i < sap.degree
                    algebra::G1_vector<CurveType> G_gamma2_Z_t;

                    r1cs_se_ppzksnark_constraint_system<CurveType> constraint_system;

                    r1cs_se_ppzksnark_proving_key() {};
                    r1cs_se_ppzksnark_proving_key<CurveType> &
                        operator=(const r1cs_se_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_se_ppzksnark_proving_key(const r1cs_se_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_se_ppzksnark_proving_key(r1cs_se_ppzksnark_proving_key<CurveType> &&other) = default;
                    r1cs_se_ppzksnark_proving_key(algebra::G1_vector<CurveType> &&A_query,
                                                  algebra::G2_vector<CurveType> &&B_query,
                                                  algebra::G1_vector<CurveType> &&C_query_1,
                                                  algebra::G1_vector<CurveType> &&C_query_2,
                                                  algebra::G1<CurveType> &G_gamma_Z,
                                                  algebra::G2<CurveType> &H_gamma_Z,
                                                  algebra::G1<CurveType> &G_ab_gamma_Z,
                                                  algebra::G1<CurveType> &G_gamma2_Z2,
                                                  algebra::G1_vector<CurveType> &&G_gamma2_Z_t,
                                                  r1cs_se_ppzksnark_constraint_system<CurveType> &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query_1(std::move(C_query_1)), C_query_2(std::move(C_query_2)),
                        G_gamma_Z(G_gamma_Z), H_gamma_Z(H_gamma_Z), G_ab_gamma_Z(G_ab_gamma_Z),
                        G_gamma2_Z2(G_gamma2_Z2), G_gamma2_Z_t(std::move(G_gamma2_Z_t)),
                        constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return A_query.size() + C_query_1.size() + C_query_2.size() + 3 + G_gamma2_Z_t.size();
                    }

                    std::size_t G2_size() const {
                        return B_query.size() + 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * algebra::G1<CurveType>::size_in_bits() +
                               G2_size() * algebra::G2<CurveType>::size_in_bits();
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in PK: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* G2 elements in PK: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* PK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_se_ppzksnark_proving_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                         const r1cs_se_ppzksnark_proving_key<CurveType> &pk);
                    friend std::istream &operator>><CurveType>(std::istream &in, r1cs_se_ppzksnark_proving_key<CurveType> &pk);
                };

                /******************************* Verification key ****************************/

                template<typename CurveType>
                class r1cs_se_ppzksnark_verification_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_verification_key<CurveType> &vk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_verification_key<CurveType> &vk);

                /**
                 * A verification key for the R1CS SEppzkSNARK.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_verification_key {
                public:
                    // H
                    algebra::G2<CurveType> H;

                    // G^{alpha}
                    algebra::G1<CurveType> G_alpha;

                    // H^{beta}
                    algebra::G2<CurveType> H_beta;

                    // G^{gamma}
                    algebra::G1<CurveType> G_gamma;

                    // H^{gamma}
                    algebra::G2<CurveType> H_gamma;

                    // G^{gamma * A_i(t) + (alpha + beta) * A_i(t)}
                    // for 0 <= i <= sap.num_inputs()
                    algebra::G1_vector<CurveType> query;

                    r1cs_se_ppzksnark_verification_key() = default;
                    r1cs_se_ppzksnark_verification_key(const algebra::G2<CurveType> &H,
                                                       const algebra::G1<CurveType> &G_alpha,
                                                       const algebra::G2<CurveType> &H_beta,
                                                       const algebra::G1<CurveType> &G_gamma,
                                                       const algebra::G2<CurveType> &H_gamma,
                                                       algebra::G1_vector<CurveType> &&query) :
                        H(H),
                        G_alpha(G_alpha), H_beta(H_beta), G_gamma(G_gamma), H_gamma(H_gamma),
                        query(std::move(query)) {};

                    std::size_t G1_size() const {
                        return 2 + query.size();
                    }

                    std::size_t G2_size() const {
                        return 3;
                    }

                    std::size_t size_in_bits() const {
                        return (G1_size() * algebra::G1<CurveType>::size_in_bits() +
                                G2_size() * algebra::G2<CurveType>::size_in_bits());
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in VK: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* G2 elements in VK: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* VK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_se_ppzksnark_verification_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                         const r1cs_se_ppzksnark_verification_key<CurveType> &vk);
                    friend std::istream &operator>><CurveType>(std::istream &in, r1cs_se_ppzksnark_verification_key<CurveType> &vk);

                    static r1cs_se_ppzksnark_verification_key<CurveType> dummy_verification_key(const std::size_t input_size);
                };

                /************************ Processed verification key *************************/

                template<typename CurveType>
                class r1cs_se_ppzksnark_processed_verification_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk);

                /**
                 * A processed verification key for the R1CS SEppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_processed_verification_key {
                public:
                    algebra::G1<CurveType> G_alpha;
                    algebra::G2<CurveType> H_beta;
                    algebra::Fqk<CurveType> G_alpha_H_beta_ml;
                    algebra::G1_precomp<CurveType> G_gamma_pc;
                    algebra::G2_precomp<CurveType> H_gamma_pc;
                    algebra::G2_precomp<CurveType> H_pc;

                    algebra::G1_vector<CurveType> query;

                    bool operator==(const r1cs_se_ppzksnark_processed_verification_key &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                         const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk);
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS SEppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_keypair {
                public:
                    r1cs_se_ppzksnark_proving_key<CurveType> pk;
                    r1cs_se_ppzksnark_verification_key<CurveType> vk;

                    r1cs_se_ppzksnark_keypair() = default;
                    r1cs_se_ppzksnark_keypair(const r1cs_se_ppzksnark_keypair<CurveType> &other) = default;
                    r1cs_se_ppzksnark_keypair(r1cs_se_ppzksnark_proving_key<CurveType> &&pk,
                                              r1cs_se_ppzksnark_verification_key<CurveType> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    r1cs_se_ppzksnark_keypair(r1cs_se_ppzksnark_keypair<CurveType> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                template<typename CurveType>
                class r1cs_se_ppzksnark_proof;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_proof<CurveType> &proof);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * A proof for the R1CS SEppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_proof {
                public:
                    algebra::G1<CurveType> A;
                    algebra::G2<CurveType> B;
                    algebra::G1<CurveType> C;

                    r1cs_se_ppzksnark_proof() {
                    }
                    r1cs_se_ppzksnark_proof(algebra::G1<CurveType> &&A, algebra::G2<CurveType> &&B, algebra::G1<CurveType> &&C) :
                        A(std::move(A)), B(std::move(B)), C(std::move(C)) {};

                    std::size_t G1_size() const {
                        return 2;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * algebra::G1<CurveType>::size_in_bits() +
                               G2_size() * algebra::G2<CurveType>::size_in_bits();
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in proof: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* G2 elements in proof: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* Proof size in bits: %zu\n", this->size_in_bits());
                    }

                    bool is_well_formed() const {
                        return (A.is_well_formed() && B.is_well_formed() && C.is_well_formed());
                    }

                    bool operator==(const r1cs_se_ppzksnark_proof<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out, const r1cs_se_ppzksnark_proof<CurveType> &proof);
                    friend std::istream &operator>><CurveType>(std::istream &in, r1cs_se_ppzksnark_proof<CurveType> &proof);
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS SEppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_keypair<CurveType>
                    r1cs_se_ppzksnark_generator(const r1cs_se_ppzksnark_constraint_system<CurveType> &cs);

                /**
                 * A prover algorithm for the R1CS SEppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_proof<CurveType>
                    r1cs_se_ppzksnark_prover(const r1cs_se_ppzksnark_proving_key<CurveType> &pk,
                                             const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                             const r1cs_se_ppzksnark_auxiliary_input<CurveType> &auxiliary_input);

                /*
                 Below are four variants of verifier algorithm for the R1CS SEppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= CS.num_inputs (and
                     the primary input is implicitly padded with zeros up to length CS.num_inputs).
                 */

                /**
                 * A verifier algorithm for the R1CS SEppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_weak_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                        const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                        const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS SEppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_strong_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                          const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                          const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_processed_verification_key<CurveType>
                    r1cs_se_ppzksnark_verifier_process_vk(const r1cs_se_ppzksnark_verification_key<CurveType> &vk);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_weak_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_strong_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof);

                template<typename CurveType>
                bool r1cs_se_ppzksnark_proving_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_proving_key<CurveType> &other) const {
                    return (this->A_query == other.A_query && this->B_query == other.B_query &&
                            this->C_query_1 == other.C_query_1 && this->C_query_2 == other.C_query_2 &&
                            this->G_gamma_Z == other.G_gamma_Z && this->H_gamma_Z == other.H_gamma_Z &&
                            this->G_ab_gamma_Z == other.G_ab_gamma_Z && this->G_gamma2_Z2 == other.G_gamma2_Z2 &&
                            this->G_gamma2_Z_t == other.G_gamma2_Z_t &&
                            this->constraint_system == other.constraint_system);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_proving_key<CurveType> &pk) {
                    out << pk.A_query;
                    out << pk.B_query;
                    out << pk.C_query_1;
                    out << pk.C_query_2;
                    out << pk.G_gamma_Z;
                    out << pk.H_gamma_Z;
                    out << pk.G_ab_gamma_Z;
                    out << pk.G_gamma2_Z2;
                    out << pk.G_gamma2_Z_t;
                    out << pk.constraint_system;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_proving_key<CurveType> &pk) {
                    in >> pk.A_query;
                    in >> pk.B_query;
                    in >> pk.C_query_1;
                    in >> pk.C_query_2;
                    in >> pk.G_gamma_Z;
                    in >> pk.H_gamma_Z;
                    in >> pk.G_ab_gamma_Z;
                    in >> pk.G_gamma2_Z2;
                    in >> pk.G_gamma2_Z_t;
                    in >> pk.constraint_system;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verification_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_verification_key<CurveType> &other) const {
                    return (this->H == other.H && this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                            this->G_gamma == other.G_gamma && this->H_gamma == other.H_gamma &&
                            this->query == other.query);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_verification_key<CurveType> &vk) {
                    out << vk.H << OUTPUT_NEWLINE;
                    out << vk.G_alpha << OUTPUT_NEWLINE;
                    out << vk.H_beta << OUTPUT_NEWLINE;
                    out << vk.G_gamma << OUTPUT_NEWLINE;
                    out << vk.H_gamma << OUTPUT_NEWLINE;
                    out << vk.query << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_verification_key<CurveType> &vk) {
                    in >> vk.H;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.G_alpha;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.H_beta;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.G_gamma;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.H_gamma;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.query;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_processed_verification_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &other) const {
                    return (this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                            this->G_alpha_H_beta_ml == other.G_alpha_H_beta_ml &&
                            this->G_gamma_pc == other.G_gamma_pc && this->H_gamma_pc == other.H_gamma_pc &&
                            this->H_pc == other.H_pc && this->query == other.query);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk) {
                    out << pvk.G_alpha << OUTPUT_NEWLINE;
                    out << pvk.H_beta << OUTPUT_NEWLINE;
                    out << pvk.G_alpha_H_beta_ml << OUTPUT_NEWLINE;
                    out << pvk.G_gamma_pc << OUTPUT_NEWLINE;
                    out << pvk.H_gamma_pc << OUTPUT_NEWLINE;
                    out << pvk.H_pc << OUTPUT_NEWLINE;
                    out << pvk.query << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk) {
                    in >> pvk.G_alpha;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.H_beta;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.G_alpha_H_beta_ml;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.G_gamma_pc;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.H_gamma_pc;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.H_pc;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.query;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_proof<CurveType>::operator==(const r1cs_se_ppzksnark_proof<CurveType> &other) const {
                    return (this->A == other.A && this->B == other.B && this->C == other.C);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    out << proof.A << OUTPUT_NEWLINE;
                    out << proof.B << OUTPUT_NEWLINE;
                    out << proof.C << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    in >> proof.A;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.B;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.C;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_verification_key<CurveType>
                    r1cs_se_ppzksnark_verification_key<CurveType>::dummy_verification_key(const std::size_t input_size) {
                    r1cs_se_ppzksnark_verification_key<CurveType> result;
                    result.H = typename CurveType::scalar_field_type::random_element() * algebra::G2<CurveType>::one();
                    result.G_alpha = typename CurveType::scalar_field_type::random_element() * algebra::G1<CurveType>::one();
                    result.H_beta = typename CurveType::scalar_field_type::random_element() * algebra::G2<CurveType>::one();
                    result.G_gamma = typename CurveType::scalar_field_type::random_element() * algebra::G1<CurveType>::one();
                    result.H_gamma = typename CurveType::scalar_field_type::random_element() * algebra::G2<CurveType>::one();

                    algebra::G1_vector<CurveType> v;
                    for (std::size_t i = 0; i < input_size + 1; ++i) {
                        v.emplace_back(typename CurveType::scalar_field_type::random_element() * algebra::G1<CurveType>::one());
                    }
                    result.query = std::move(v);

                    return result;
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_keypair<CurveType>
                    r1cs_se_ppzksnark_generator(const r1cs_se_ppzksnark_constraint_system<CurveType> &cs) {

                    /**
                     * draw random element t at which the SAP is evaluated.
                     * it should be the case that Z(t) != 0
                     */
                    const std::shared_ptr<algebra::fft::evaluation_domain<typename CurveType::scalar_field_type>> domain =
                        r1cs_to_sap_get_domain(cs);
                    typename CurveType::scalar_field_type t;
                    do {
                        t = typename CurveType::scalar_field_type::random_element();
                    } while (domain->compute_vanishing_polynomial(t).is_zero());

                    sap_instance_evaluation<typename CurveType::scalar_field_type> sap_inst =
                        r1cs_to_sap_instance_map_with_evaluation(cs, t);

                    std::size_t non_zero_At = 0;
                    for (std::size_t i = 0; i < sap_inst.num_variables() + 1; ++i) {
                        if (!sap_inst.At[i].is_zero()) {
                            ++non_zero_At;
                        }
                    }

                    algebra::Fr_vector<CurveType> At = std::move(sap_inst.At);
                    algebra::Fr_vector<CurveType> Ct = std::move(sap_inst.Ct);
                    algebra::Fr_vector<CurveType> Ht = std::move(sap_inst.Ht);
                    /**
                     * sap_inst.{A,C,H}t are now in an unspecified state,
                     * but we do not use them below
                     */

                    const typename CurveType::scalar_field_type alpha = typename CurveType::scalar_field_type::random_element(),
                                           beta = typename CurveType::scalar_field_type::random_element(),
                                           gamma = typename CurveType::scalar_field_type::random_element();
                    const algebra::G1<CurveType> G = algebra::G1<CurveType>::random_element();
                    const algebra::G2<CurveType> H = algebra::G2<CurveType>::random_element();

                    std::size_t G_exp_count = sap_inst.num_inputs() + 1    // verifier_query
                                         + non_zero_At                // A_query
                                         + sap_inst.degree() +
                                         1    // G_gamma2_Z_t
                                         // C_query_1
                                         + sap_inst.num_variables() - sap_inst.num_inputs() + sap_inst.num_variables() +
                                         1,    // C_query_2
                        G_window = algebra::get_exp_window_size<algebra::G1<CurveType>>(G_exp_count);

                    algebra::window_table<algebra::G1<CurveType>> G_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits(), G_window, G);

                    algebra::G2<CurveType> H_gamma = gamma * H;
                    std::size_t H_gamma_exp_count = non_zero_At,    // B_query
                        H_gamma_window = algebra::get_exp_window_size<algebra::G2<CurveType>>(H_gamma_exp_count);
                    algebra::window_table<algebra::G2<CurveType>> H_gamma_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits(), H_gamma_window, H_gamma);

                    algebra::G1<CurveType> G_alpha = alpha * G;
                    algebra::G2<CurveType> H_beta = beta * H;

                    algebra::Fr_vector<CurveType> tmp_exponents;
                    tmp_exponents.reserve(sap_inst.num_inputs() + 1);
                    for (std::size_t i = 0; i <= sap_inst.num_inputs(); ++i) {
                        tmp_exponents.emplace_back(gamma * Ct[i] + (alpha + beta) * At[i]);
                    }
                    algebra::G1_vector<CurveType> verifier_query = algebra::batch_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();

                    tmp_exponents.reserve(sap_inst.num_variables() + 1);
                    for (std::size_t i = 0; i < At.size(); i++) {
                        tmp_exponents.emplace_back(gamma * At[i]);
                    }

                    algebra::G1_vector<CurveType> A_query = algebra::batch_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<CurveType>>(A_query);
#endif
                    algebra::G2_vector<CurveType> B_query = algebra::batch_exp<algebra::G2<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), H_gamma_window, H_gamma_table, At);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G2<CurveType>>(B_query);
#endif
                    algebra::G1<CurveType> G_gamma = gamma * G;
                    algebra::G1<CurveType> G_gamma_Z = sap_inst.Zt * G_gamma;
                    algebra::G2<CurveType> H_gamma_Z = sap_inst.Zt * H_gamma;
                    algebra::G1<CurveType> G_ab_gamma_Z = (alpha + beta) * G_gamma_Z;
                    algebra::G1<CurveType> G_gamma2_Z2 = (sap_inst.Zt * gamma) * G_gamma_Z;

                    tmp_exponents.reserve(sap_inst.degree() + 1);

                    /* Compute the vector G_gamma2_Z_t := Z(t) * t^i * gamma^2 * G */
                    typename CurveType::scalar_field_type gamma2_Z_t = sap_inst.Zt * gamma.squared();
                    for (std::size_t i = 0; i < sap_inst.degree() + 1; ++i) {
                        tmp_exponents.emplace_back(gamma2_Z_t);
                        gamma2_Z_t *= t;
                    }
                    algebra::G1_vector<CurveType> G_gamma2_Z_t = algebra::batch_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<CurveType>>(G_gamma2_Z_t);
#endif
                    tmp_exponents.reserve(sap_inst.num_variables() - sap_inst.num_inputs());
                    for (std::size_t i = sap_inst.num_inputs() + 1; i <= sap_inst.num_variables(); ++i) {
                        tmp_exponents.emplace_back(gamma * (gamma * Ct[i] + (alpha + beta) * At[i]));
                    }
                    algebra::G1_vector<CurveType> C_query_1 = algebra::batch_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<CurveType>>(C_query_1);
#endif

                    tmp_exponents.reserve(sap_inst.num_variables() + 1);
                    typename CurveType::scalar_field_type double_gamma2_Z = gamma * gamma * sap_inst.Zt;
                    double_gamma2_Z = double_gamma2_Z + double_gamma2_Z;
                    for (std::size_t i = 0; i <= sap_inst.num_variables(); ++i) {
                        tmp_exponents.emplace_back(double_gamma2_Z * At[i]);
                    }
                    algebra::G1_vector<CurveType> C_query_2 = algebra::batch_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::size_in_bits(), G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<CurveType>>(C_query_2);
#endif

                    r1cs_se_ppzksnark_verification_key<CurveType> vk = r1cs_se_ppzksnark_verification_key<CurveType>(
                        H, G_alpha, H_beta, G_gamma, H_gamma, std::move(verifier_query));

                    r1cs_se_ppzksnark_constraint_system<CurveType> cs_copy(cs);

                    r1cs_se_ppzksnark_proving_key<CurveType> pk = r1cs_se_ppzksnark_proving_key<CurveType>(
                        std::move(A_query), std::move(B_query), std::move(C_query_1), std::move(C_query_2), G_gamma_Z,
                        H_gamma_Z, G_ab_gamma_Z, G_gamma2_Z2, std::move(G_gamma2_Z_t), std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return r1cs_se_ppzksnark_keypair<CurveType>(std::move(pk), std::move(vk));
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_proof<CurveType>
                    r1cs_se_ppzksnark_prover(const r1cs_se_ppzksnark_proving_key<CurveType> &pk,
                                             const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                             const r1cs_se_ppzksnark_auxiliary_input<CurveType> &auxiliary_input) {

                    const typename CurveType::scalar_field_type d1 = typename CurveType::scalar_field_type::random_element(),
                                           d2 = typename CurveType::scalar_field_type::random_element();

                    const sap_witness<typename CurveType::scalar_field_type> sap_wit =
                        r1cs_to_sap_witness_map(pk.constraint_system, primary_input, auxiliary_input, d1, d2);

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    const typename CurveType::scalar_field_type r = typename CurveType::scalar_field_type::random_element();

                    /**
                     * compute A = G^{gamma * (\sum_{i=0}^m input_i * A_i(t) + r * Z(t))}
                     *           = \prod_{i=0}^m (G^{gamma * A_i(t)})^{input_i)
                     *             * (G^{gamma * Z(t)})^r
                     *           = \prod_{i=0}^m A_query[i]^{input_i} * G_gamma_Z^r
                     */
                    algebra::G1<CurveType> A =
                        r * pk.G_gamma_Z + pk.A_query[0] +    // i = 0 is a special case because input_i = 1
                        sap_wit.d1 * pk.G_gamma_Z +           // ZK-patch
                        algebra::multi_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.A_query.begin() + 1,
                            pk.A_query.end(),
                            sap_wit.coefficients_for_ACs.begin(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks);

                    /**
                     * compute B exactly as A, except with H as the base
                     */
                    algebra::G2<CurveType> B =
                        r * pk.H_gamma_Z + pk.B_query[0] +    // i = 0 is a special case because input_i = 1
                        sap_wit.d1 * pk.H_gamma_Z +           // ZK-patch
                        algebra::multi_exp<algebra::G2<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.B_query.begin() + 1,
                            pk.B_query.end(),
                            sap_wit.coefficients_for_ACs.begin(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks);
                    /**
                     * compute C = G^{f(input) +
                     *                r^2 * gamma^2 * Z(t)^2 +
                     *                r * (alpha + beta) * gamma * Z(t) +
                     *                2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t) +
                     *                gamma^2 * Z(t) * H(t)}
                     * where G^{f(input)} = \prod_{i=l+1}^m C_query_1 * input_i
                     * and G^{2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t)} =
                     *              = \prod_{i=0}^m C_query_2 * input_i
                     */
                    algebra::G1<CurveType> C =
                        algebra::multi_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.C_query_1.begin(),
                            pk.C_query_1.end(),
                            sap_wit.coefficients_for_ACs.begin() + sap_wit.num_inputs(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks) +
                        (r * r) * pk.G_gamma2_Z2 + r * pk.G_ab_gamma_Z + sap_wit.d1 * pk.G_ab_gamma_Z +    // ZK-patch
                        r * pk.C_query_2[0] +                      // i = 0 is a special case for C_query_2
                        (r + r) * sap_wit.d1 * pk.G_gamma2_Z2 +    // ZK-patch for C_query_2
                        r * algebra::multi_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                                pk.C_query_2.begin() + 1,
                                pk.C_query_2.end(),
                                sap_wit.coefficients_for_ACs.begin(),
                                sap_wit.coefficients_for_ACs.end(),
                                chunks) +
                        sap_wit.d2 * pk.G_gamma2_Z_t[0] +    // ZK-patch
                        algebra::multi_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.G_gamma2_Z_t.begin(),
                            pk.G_gamma2_Z_t.end(),
                            sap_wit.coefficients_for_H.begin(),
                            sap_wit.coefficients_for_H.end(),
                            chunks);

                    r1cs_se_ppzksnark_proof<CurveType> proof =
                        r1cs_se_ppzksnark_proof<CurveType>(std::move(A), std::move(B), std::move(C));
                    proof.print_size();

                    return proof;
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_processed_verification_key<CurveType>
                    r1cs_se_ppzksnark_verifier_process_vk(const r1cs_se_ppzksnark_verification_key<CurveType> &vk) {

                    algebra::G1_precomp<CurveType> G_alpha_pc = CurveType::precompute_G1(vk.G_alpha);
                    algebra::G2_precomp<CurveType> H_beta_pc = CurveType::precompute_G2(vk.H_beta);

                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk;
                    pvk.G_alpha = vk.G_alpha;
                    pvk.H_beta = vk.H_beta;
                    pvk.G_alpha_H_beta_ml = CurveType::miller_loop(G_alpha_pc, H_beta_pc);
                    pvk.G_gamma_pc = CurveType::precompute_G1(vk.G_gamma);
                    pvk.H_gamma_pc = CurveType::precompute_G2(vk.H_gamma);
                    pvk.H_pc = CurveType::precompute_G2(vk.H);

                    pvk.query = vk.query;

                    return pvk;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_weak_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof) {

                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    /**
                     * e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
                     *                              * e(C, H)
                     * where psi = \sum_{i=0}^l input_i pvk.query[i]
                     */
                    algebra::G1<CurveType> G_psi =
                        pvk.query[0] +
                        algebra::multi_exp<algebra::G1<CurveType>, typename CurveType::scalar_field_type, algebra::multi_exp_method_bos_coster>(
                            pvk.query.begin() + 1, pvk.query.end(), primary_input.begin(), primary_input.end(), chunks);

                    algebra::Fqk<CurveType> test1_l = CurveType::miller_loop(CurveType::precompute_G1(proof.A + pvk.G_alpha),
                                                                 CurveType::precompute_G2(proof.B + pvk.H_beta)),
                                      test1_r1 = pvk.G_alpha_H_beta_ml,
                                      test1_r2 = CurveType::miller_loop(CurveType::precompute_G1(G_psi), pvk.H_gamma_pc),
                                      test1_r3 = CurveType::miller_loop(CurveType::precompute_G1(proof.C), pvk.H_pc);
                    algebra::GT<CurveType> test1 =
                        CurveType::final_exponentiation(test1_l.unitary_inverse() * test1_r1 * test1_r2 * test1_r3);

                    if (test1 != algebra::GT<CurveType>::one()) {
                        result = false;
                    }

                    /**
                     * e(A, H^{gamma}) = e(G^{gamma}, B)
                     */
                    algebra::Fqk<CurveType> test2_l = CurveType::miller_loop(CurveType::precompute_G1(proof.A), pvk.H_gamma_pc),
                                      test2_r = CurveType::miller_loop(pvk.G_gamma_pc, CurveType::precompute_G2(proof.B));
                    algebra::GT<CurveType> test2 = CurveType::final_exponentiation(test2_l * test2_r.unitary_inverse());

                    if (test2 != algebra::GT<CurveType>::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_weak_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                        const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                        const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk =
                        r1cs_se_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_se_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_strong_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    bool result = true;

                    if (pvk.query.size() != primary_input.size() + 1) {
                        result = false;
                    } else {
                        result = r1cs_se_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_strong_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                          const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                          const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk =
                        r1cs_se_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_se_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_SE_PPZKSNARK_HPP_
