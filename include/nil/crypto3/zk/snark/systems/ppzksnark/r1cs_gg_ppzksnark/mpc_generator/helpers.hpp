//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_PHASE2_MPC_PARAMS_HPP
#define CRYPTO3_R1CS_PHASE2_MPC_PARAMS_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/mpc_params.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <vector>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/mpc/mpc_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_mpc_generator_helpers {
                    typedef CurveType curve_type;
                    typedef r1cs_gg_ppzksnark<curve_type> proving_scheme_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_private_key<curve_type> private_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_generator_public_key<curve_type> public_key_type;
                    typedef r1cs_gg_ppzksnark_mpc_params<curve_type> mpc_params_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using kc_type = commitments::knowledge_commitment<g2_type, g1_type>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using kc_value_type = typename kc_type::value_type;
                    using scalar_field_type = typename curve_type::scalar_field_type; 
                    using scalar_field_value_type = typename scalar_field_type::value_type; 

                public:
                    std::pair<public_key_type, private_key_type> generate_keypair(const public_key_type & previous_pubkey,
                                                                                  const std::array<std::uint8_t, 64> &transcript) {
                        private_key_type sk {
                            algebra::random_element<scalar_field_type>()
                        };
                        
                        auto delta_pok = construct_pok(sk.delta, transcript);
                        public_key_type pk {
                            sk.delta * previous_pubkey.delta_after,
                            delta_pok
                        };

                        return {pk, sk};
                    }

                    static proof_of_knowledge<CurveType>
                        construct_pok(scalar_field_value_type x,
                           const std::vector<std::uint8_t> &transcript,
                           std::uint8_t personalization) {
                            const g1_value_type g1_s = algebra::random_element<g1_type>(boost::random_device());
                            const g1_value_type g1_s_x = x * g1_s;
                            auto g2_s = compute_g2_s(g1_s, g1_s_x, transcript, personalization);
                            auto g2_s_x = x * g2_s;
                            return proof_of_knowledge<CurveType> { g1_s, g1_s_x, g2_s_x };
                    }

                    static std::vector<std::uint8_t> serialize_mpc_params(const mpc_params_type &params) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val = nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_mpc_params<mpc_params_type, endianness>(params);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        return blob;
                    }

                    static std::vector<std::uint8_t> compute_transcript(const mpc_params_type &params) {
                        auto params_blob = serialize_mpc_params(params);
                        return nil::crypto3::hash<hashes::blake2b<512>>(params_blob);
                    }

                    static g2_value_type compute_g2_s(g1_value_type g1_s, g1_value_type g1_s_x, const std::vector<std::uint8_t> &transcript) {

                        std::vector<std::uint8_t> transcript_g1s_g1sx; 
                        
                        std::copy(std::cbegin(transcript),
                                    std::cend(transcript),
                                    std::back_inserter(transcript_g1s_g1sx));
                        
                        auto g1_s_blob = serialize_g1_uncompressed(g1_s);
                        std::copy(std::cbegin(g1_s_blob),
                                    std::cend(g1_s_blob),
                                    std::back_inserter(g1_s_blob));
                        
                        auto g1_s_x_blob = serialize_g1_uncompressed(g1_s_x);
                        std::copy(std::cbegin(g1_s_x_blob),
                                    std::cend(g1_s_x_blob),
                                    std::back_inserter(g1_s_x_blob));

                        std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::blake2b<256>>(transcript_g1s_g1sx);
                        
                        // in the rust version chacha rng is used, but chacha rng is broken right now.
                        // the current solution is obviously not secure at all, but it's just a placeholder
                        boost::random::mt19937 gen;
                        gen.seed(hash[0]);
                        return algebra::random_element<g2_type>(gen);
                    }


               private:
                    // template<typename PointIterator, typename ScalarIterator>
                    // void naive_batch_exp(const PointIterator &bases_begin,
                    //                     const PointIterator &bases_end,
                    //                     const ScalarIterator &pow_begin,
                    //                     const ScalarIterator &pow_end) {
                    //     BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));
                        
                    //     auto base_iter = bases_begin;
                    //     auto pow_iter = pow_begin;
                    //     while(base_iter < bases_end) {
                    //         *base_iter = *pow_iter * *base_iter;
                    //         ++base_iter;
                    //         ++pow_iter;
                    //     }
                    // }

                    // template<typename PointIterator, typename ScalarIterator>
                    // void naive_batch_exp_with_coeff(const PointIterator &bases_begin,
                    //                     const PointIterator &bases_end,
                    //                     const ScalarIterator &pow_begin,
                    //                     const ScalarIterator &pow_end,
                    //                     const field_value_type & coeff) {
                    //     BOOST_ASSERT(std::distance(bases_begin, bases_end) <= std::distance(pow_begin, pow_end));
                        
                    //     auto base_iter = bases_begin;
                    //     auto pow_iter = pow_begin;
                    //     while(base_iter < bases_end) {
                    //         *base_iter = (coeff * *pow_iter) * *base_iter;
                    //         ++base_iter;
                    //         ++pow_iter;
                    //     }
                    // }
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_PHASE2_MPC_PARAMS_HPP
