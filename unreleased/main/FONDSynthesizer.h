/*
* declares class FONDSynthesizer
* implements synthesis in FOND domains
*/

#ifndef SYFT_FONDSYNTHESIZER_H
#define SYFT_FONDSYNTHESIZER_H

#include<memory>
#include<string>
#include<stdlib.h>
#include<math.h>
#include<boost/algorithm/string/predicate.hpp>
#include"VarMgr.h"
#include"ExplicitStateDfaMona.h"
#include"ExplicitStateDfa.h"
#include"SymbolicStateDfa.h"
#include"ReachabilitySynthesizer.h"
#include"CoOperativeReachabilitySynthesizer.h"
#include"Domain.h"
#include"Stopwatch.h"

namespace Syft {

    class FONDSynthesizer {

        protected:
            std::shared_ptr<Syft::VarMgr> var_mgr_;

            std::string domain_file_;
            std::string problem_file_;

            bool interactive_;

            std::vector<double> running_times_;

        public:

            FONDSynthesizer(std::shared_ptr<Syft::VarMgr> var_mgr,
                const std::string& domain_file,
                const std::string& problem_file,
                bool interactive
            );

            virtual Syft::SynthesisResult run() final;

            void interactive(
                const Domain& domain,
                const SymbolicStateDfa& domain_dfa,
                const SynthesisResult& result) const;

            std::vector<double> get_running_times() const {return running_times_;}

        private:
            std::vector<int> to_bits(int i, std::size_t size) const;

            int to_int(const std::vector<int>& bits) const;
    };      

} 
#endif