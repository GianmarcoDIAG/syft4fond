/*
* declares class Domain
* represents FOND domain with action and reaction
* as in [De Giacomo, Parretti, and Zhu, ECAI 2023]
*/

#ifndef DOMAIN_H
#define DOMAIN_H

#include<string>
#include<fstream>
#include<boost/algorithm/string/predicate.hpp>
#include<boost/algorithm/string/classification.hpp>
#include<boost/algorithm/string/split.hpp>
#include<boost/algorithm/string/trim.hpp>
#include<boost/algorithm/string/replace.hpp>
#include<boost/algorithm/string.hpp>
#include<unordered_set>
#include<cuddObj.hh>
#include"SymbolicStateDfa.h"

// TODO. Add general documentation to all functions in the classes
namespace Syft {

    class Domain {

        class Action {
            std::string action_name_;
            // add_list_ (resp. delete_list_) is a vector of integers
            // value determines the var (by its index) added (resp. deleted)
            // pos_precondition_ (resp. neg_preconidtion_) is a vector of integers
            // value determines var that must (resp. must not) hold (by its index)
            std::unordered_set<int> pos_precondition_;
            std::unordered_set<int> neg_precondition_;
            std::unordered_set<int> add_list_;
            std::unordered_set<int> delete_list_;
            // BDDs representing agent action
            // action_bdd_ represents the whole action-reaction
            // agent_bdd_ represents the agent action
            // env_bdd_ represents the env reaction
            CUDD::BDD action_bdd_;
            CUDD::BDD agent_bdd_;
            CUDD::BDD env_bdd_;

            // agent_prop_ is a propositional formula that represents action
            std::string agent_prop_;

            public:

                bool operator==(const Action& rhs) const {
                    return action_name_ == rhs.action_name_;
                }

                Action(
                    std::string action_name,
                    std::unordered_set<int> pos_precondition,
                    std::unordered_set<int> neg_precondition,
                    std::unordered_set<int> add_list,
                    std::unordered_set<int> delete_list
                ) : action_name_(action_name),
                    pos_precondition_(pos_precondition),
                    neg_precondition_(neg_precondition),
                    add_list_(add_list),
                    delete_list_(delete_list) {} 

                std::string get_action_name() const {
                    return action_name_;
                }

                CUDD::BDD get_action_bdd() const {
                    return action_bdd_;
                }

                CUDD::BDD get_agent_bdd() const {
                    return agent_bdd_;
                }

                CUDD::BDD get_env_bdd() const {
                    return env_bdd_;
                }

                std::unordered_set<int> get_add_list() const {
                    return add_list_;
                }

                std::unordered_set<int> get_del_list() const {
                    return delete_list_;
                }

                std::unordered_set<int> get_pos_pre() const {
                    return pos_precondition_;
                }

                std::unordered_set<int> get_neg_pre() const {
                    return neg_precondition_;
                }

                std::string get_action_prop() const {
                    return agent_prop_;
                }

                // void set_action_bin(const std::vector<int>& agent_bin) {
                    // agent_bin_ = agent_bin; 
                // }

                // void set_env_bin(const std::vector<int>& env_bin) {
                    // env_bin_ = env_bin;
                // }

                void set_action_bdd(const CUDD::BDD& bdd) {
                    action_bdd_ = bdd;
                }

                void set_agent_bdd(const CUDD::BDD& agent_bdd) {
                    agent_bdd_ = agent_bdd;
                }

                void set_env_bdd(const CUDD::BDD& env_bdd) {
                    env_bdd_ = env_bdd;
                }

                void set_agent_prop(const std::string& agent_prop) {
                    agent_prop_ = agent_prop;
                }

                // TODO. Add checks to determine when action-reaction encoding is undefined
                void print() const {
                    std::cout << "ACTION NAME: " << action_name_ << std::endl;
                    // std::cout << "AGENT VARS: ";
                    // for (const auto& i : agent_bin_) std::cout << i;
                    // std::cout << std::endl;
                    // std::cout << "ENV VARS: ";
                    // for (const auto& i : env_bin_) std::cout << i;
                    // std::cout << std::endl;
                    std::string precondition = "";
                    for (const auto& i : pos_precondition_) precondition += std::to_string(i) + ", "; 
                    for (const auto& i : neg_precondition_) precondition += std::to_string(i) + ", ";
                    std::cout << "PRECONDITION {" + precondition.substr(0, precondition.size() - 2) + "}" << std::endl; 
                    std::string add_list = "", delete_list = "";
                    for (const auto& i : add_list_) add_list += std::to_string(i) + ", ";
                    for (const auto& i : delete_list_) delete_list += std::to_string(i) + ", ";
                    std::cout << "ADD-LIST {" + add_list.substr(0, add_list.size() - 2) + "}" << std::endl;
                    std::cout << "DELETE-LIST {" + delete_list.substr(0, delete_list.size() - 2) + "}" << std::endl;
                }
        };

        class Invariant {
            // class to describe invariants. At most
            // one literal among pos_vars_ and meg_vars can be true
            std::unordered_set<int> pos_vars_;
            std::unordered_set<int> neg_vars_;

            public:

                Invariant(const std::unordered_set<int>& pos_vars,
                        const std::unordered_set<int>& neg_vars): 
                            pos_vars_(pos_vars),
                            neg_vars_(neg_vars) {}

                std::unordered_set<int> get_pos_vars() const {
                    return pos_vars_;
                }

                std::unordered_set<int> get_neg_vars() const {
                    return neg_vars_;
                }

                bool operator==(const Invariant& rhs) const {
                    return (pos_vars_ == rhs.pos_vars_ && neg_vars_ == rhs.neg_vars_);
                }

                void print() const {
                    std::cout << "MUTEX INVARIANT: ";
                    std::string invariant_str = "{";
                    for (const auto& v : pos_vars_) invariant_str += std::to_string(v) + ", ";
                    for (const auto& v : neg_vars_) invariant_str += std::to_string(-v) + ", ";
                    invariant_str = invariant_str.substr(0, invariant_str.size() - 2) + "}";
                    std::cout << invariant_str << std::endl;
                }
        };

        // TODO. include random number gen to make hash functions safe
        struct InvariantHash{
            size_t operator()(const Invariant& i) const {
                std::hash<int> hasher;
                size_t seed = 1;
                for (const auto& v: i.get_pos_vars()) seed *= v + 0x9e3779b9 + (seed<<6) + (seed>>2);
                for (const auto& v: i.get_neg_vars()) seed *= -v + 0xa426253b + (seed<<12) + (seed >> 33);
                return hasher(seed);
            }
        };

        struct ActionHash{
            size_t operator()(const Action& a) const {
                std::hash<std::string> hasher;
                size_t seed = 0;
                seed = hasher(a.get_action_name()) + 0x9e3779b9 + (seed<<6) + (seed>>2);
                return seed;
            }
        };

        struct BDDHash{
            std::size_t operator()(const CUDD::BDD& bdd) const {
                std::hash<int> hasher;
                std::size_t seed = 0;
                seed = hasher(bdd.NodeReadIndex()) + 0x9e37463a + (seed<<8) + (seed>>1);;
                return seed;
            }
        };

        // data members go here
        protected:
            std::shared_ptr<Syft::VarMgr> var_mgr_;

            // We use an std::vector to store variables
            // the index of var is also used for accessing it
            std::vector<std::string> vars_;

            // In init_state_, i-th entry is the initial value
            // of i-th var
            std::vector<int> init_state_;

            // goal_list_ is a vector of integers 
            // values determine index of vars_ which should (resp. not) hold in final states
            std::unordered_set<int> pos_goal_list_;
            std::unordered_set<int> neg_goal_list_;

            std::unordered_set<Action, ActionHash> actions_;

            std::vector<std::string> action_vars_;
            std::vector<std::string> reaction_vars_;

            std::map<int, std::string> id_to_action_name_;
            std::map<int, std::string> id_to_reaction_name_;

            std::unordered_set<Invariant, InvariantHash> invariants_;

            CUDD::BDD invariants_bdd_;
        public: 
            /**
             * \brief construct FOND domain from PDDL domain and problem file
             * 
             * \param domain_file path to PDDL domain file
             * \param problem_file path to PDDL problem file
             * 
             * \return Domain object representing FOND domain
            */
            Domain(
                std::shared_ptr<Syft::VarMgr> var_mgr,
                const std::string& domain_file,
                const std::string& problem_file
            );

            std::vector<std::string> get_vars() const {
                return vars_;
            }

            std::vector<std::string> get_action_vars() const {
                return action_vars_;
            }

            std::vector<std::string> get_reaction_vars() const {
                return reaction_vars_;
            }

            std::map<int, std::string> get_id_to_action_name() const {
                return id_to_action_name_;
            }

            std::map<int, std::string> get_id_to_reaction_name() const {
                return id_to_reaction_name_;
            }

            std::vector<int> get_init_state() const {
                return init_state_;
            }

            void add_invariant(const Invariant& i) {
                invariants_.insert(i);
            }

            CUDD::BDD get_invariants_bdd() const {
                return invariants_bdd_;
            }

            SymbolicStateDfa to_symbolic();

            void print_domain() const;

        private:
            std::size_t get_bits(const std::unordered_set<std::string>& set) const;

            std::vector<int> to_bits(int i, std::size_t size) const;

            void parse_sas();

            std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> get_action_reaction_names() const;

            std::pair<std::string, CUDD::BDD> get_action_reaction_vars(const std::unordered_set<std::string>& action_names, const std::unordered_set<std::string>& reaction_names);

            std::vector<CUDD::BDD> get_transition_function(std::size_t automaton_id, const CUDD::BDD& env_mutex) const;

            CUDD::BDD get_final_states(std::size_t automaton_id) const;

            CUDD::BDD get_agent_pre(std::size_t automaton_id) const;

            std::string get_agent_error_formula(std::size_t automaton_id, const std::string& agent_mutex_axiom) const;

            CUDD::BDD get_env_pre(std::size_t automaton_id) const;

            void interactive(const SymbolicStateDfa& domain_dfa) const;

            CUDD::BDD invariant_to_bdd(std::size_t automaton_id, const Invariant& inv) const;

            // CUDD::BDD all_invariants_to_bdd(std::size_t automaton_id) const;
    };
}

#endif