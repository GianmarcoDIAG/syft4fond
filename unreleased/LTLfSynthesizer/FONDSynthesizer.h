/*
* declares class FONDSynthesizer
* implements synthesis in FOND domains
*/

#ifndef SYFT_FONDSYNTHESIZER_H
#define SYFT_FONDSYNTHESIZER_H

#include<memory>
#include<string>
#include<stdlib.h>
#include<boost/algorithm/string/predicate.hpp>
#include"VarMgr.h"
#include"ExplicitStateDfaMona.h"
#include"ExplicitStateDfa.h"
#include"SymbolicStateDfa.h"
#include"ReachabilitySynthesizer.h"
#include"CoOperativeReachabilitySynthesizer.h"
#include"Domain.h"


namespace Syft {

    class FONDSynthesizer {

        protected:
            std::shared_ptr<Syft::VarMgr> var_mgr_;

            std::string domain_file_;
            std::string problem_file_;
            std::string ltlf_goal_;

        public:

            FONDSynthesizer(std::shared_ptr<Syft::VarMgr> var_mgr,
                const std::string& domain_file,
                const std::string& problem_file,
                const std::string& ltlf_goal
            );

            virtual Syft::BestEffortSynthesisResult run() final;

            // TODO. Implement interactive debugging interface
            void interactive(
                const Domain& domain,
                const SymbolicStateDfa& domain_dfa,
                const SymbolicStateDfa& game_arena,
                const BestEffortSynthesisResult& result) const;

        private:

            /**
             * \brief construct product of domain and goal dfas as in [De Giacomo, Parretti, and Zhu, ECAI 2023] 
             * 
             * \param domain_dfa planning domain symbolic dfa
             * \param goal_dfa goal symbolic dfa
             * 
             * \return product of domain_dfa and goal_dfa
            */
            SymbolicStateDfa compose(
                const std::vector<std::string>& domain_vars,
                const std::vector<std::string>& act_vars,
                const std::vector<std::string>& react_vars,
                const std::vector<std::string>& ltlf_vars,
                const SymbolicStateDfa& domain_dfa,
                const SymbolicStateDfa& goal_dfa
            ) const;
    };      

} 
#endif