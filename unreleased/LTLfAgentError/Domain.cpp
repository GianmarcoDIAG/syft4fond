/*
* Definition of class Domain
*/

#include"Domain.h"

namespace Syft {

    Domain::Domain(
        std::shared_ptr<Syft::VarMgr> var_mgr,
        const std::string& domain_pddl,
        const std::string& problem_pddl
    ): var_mgr_(var_mgr) {
        // parse domain and problem PDDL to generate output.sas file
        std::string command = "./../../submodules/translate.py 0 " + domain_pddl + " " + problem_pddl;
        system(command.c_str());

        // read output.sas to generate data members
        parse_sas(); 
    }

    void Domain::parse_sas() {
            std::ifstream sas_input_stream("output.sas");
            std::string line;
            while (std::getline(sas_input_stream, line)) {
                // std::cout << line << std::endl;
                if (boost::starts_with(line, "Atom")) {
                    std::string var = line.substr(5);
                    boost::replace_all(var, "(", "_");
                    boost::replace_all(var, ")", "_");
                    boost::replace_all(var, " ", "");
                    boost::replace_all(var, ",", "_");
                    boost::replace_all(var, "-", "_");
                    boost::trim_if(var, boost::is_any_of("_"));
                    boost::to_lower(var);
                    vars_.push_back(var);
                } else if (boost::starts_with(line, "begin_state")) { // reads initial state information
                    while (line != "end_state") {
                        std::getline(sas_input_stream, line);
                        // in .sas 0 is "true" and 1 is "false"
                        // to match LydiaSyft: 0->1 and 1->0 in init state
                        if (line == "0") init_state_.push_back(1);
                        else if (line == "1") init_state_.push_back(0); 
                    }
                } else if (boost::starts_with(line, "begin_operator")) { // reads action information
                    std::string action_name;
                    std::unordered_set<int> pos_preconditions, neg_preconditions, add_list, delete_list;
                    while (line != "end_operator") {
                        std::getline(sas_input_stream, line);
                        if (!((boost::starts_with(line, "  ")) || line == "end_operator")) {
                            // action name
                            // preprocessing for compatibility with LydiaSyft's syntax
                            action_name = line;
                            boost::replace_all(action_name, "-", "_");
                            boost::replace_all(action_name, " ", "_");
                            boost::to_lower(action_name);
                            boost::replace_all(action_name, "detdup", "REACT");
                            auto i = action_name.find("REACT_");
                            if (i == std::string::npos) action_name = action_name + "_REACT_0";
                            else {
                                auto j = action_name.find("_", i+1);
                                auto k = action_name.find("_", j+1);
                                std::string react_id = action_name.substr(i, k-i);
                                boost::replace_all(action_name, "_" + react_id, "");
                                action_name = action_name + "_" + react_id;
                            }
                            // std::cout << "Current action name: " << action_name << std::endl;
                        } else if (boost::starts_with(line, "  ")) {
                            boost::trim(line);
                            // std::cout << line << std::endl;
                            std::vector<std::string> substr_vec;
                            boost::split(substr_vec, line, boost::is_any_of(" "));
                            int var = std::stoi(substr_vec[0].substr(1, substr_vec[0].size() - 2));
                            if (substr_vec.size() == 2) {
                                // we are handling a precondition
                                if (substr_vec[1] == "0") pos_preconditions.insert(+var);
                                else if (substr_vec[1] == "1") neg_preconditions.insert(-var);
                            } else if (substr_vec.size() == 4) {
                                // we are handling an effect
                                if (substr_vec[1] == "-1" && substr_vec[3] == "0") add_list.insert(var);
                                else if (substr_vec[1] == "1" && substr_vec[3] == "0") add_list.insert(var);
                                else if (substr_vec [1] == "0" && substr_vec[3] == "1") delete_list.insert(var);
                            }
                        }
                    }
                    Action new_action(action_name, pos_preconditions, neg_preconditions, add_list, delete_list);
                    // new_action.print();
                    actions_.insert(new_action);
                } else if (boost::starts_with(line, "begin_goal")) { // reads goal information
                    while (line != "end_goal") {
                        std::getline(sas_input_stream, line);
                        std::vector<std::string> substr_vec;
                        boost::split(substr_vec, line, boost::is_any_of(" "));
                        if (substr_vec.size() == 2) {
                            int var = std::stoi(substr_vec[0]);
                            if (substr_vec[1] == "0") pos_goal_list_.insert(var);
                            else neg_goal_list_.insert(-var);
                        }
                    }
                }
            }
            // print_domain(); 
        }
    
    SymbolicStateDfa Domain::to_symbolic() {
        // Remember the order of variables
        // (vars, act, react).

        // enable dynamic reordering for improving performance
        var_mgr_->cudd_mgr() -> AutodynEnable();

        // construct state vars of domain symbolic dfa
        // vars_.size() are vars, with indexes from 0 to vars_.size() - 1;
        // 1 is environment-error var
        // state var at index vars_.size() is env-error var
        std::cout << "Creating named state vars..." << std::flush;
        std::vector<std::string> domain_dfa_vars = vars_;
        domain_dfa_vars.push_back("env_err");
        std::size_t domain_dfa_id = var_mgr_->create_named_state_variables(domain_dfa_vars);
        std::cout << "Done!" << std::endl;

        // var_mgr_->print_varmgr();

        // DFA initial state is as domain's
        // plus two 0's denoting that
        // error vars are false in DFA initial state
        std::cout << "Creating initial state vector..." << std::flush;
        std::vector<int> dfa_initial_state = init_state_;
        dfa_initial_state.push_back(0);
        std::cout << "Done!" << std::endl;

        // define input and output vars
        // store them in var_mgr_. Use create_named_vars, create_input_vars, create_output_vars
        // assign them to actions (as conjunctions of BDDs)
        std::cout << "Computing action-reaction names..." << std::flush;
        std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> action_reaction_names 
            = get_action_reaction_names();
        std::cout << "Done!" << std::endl;

        // debug
        // std::cout << "Action names: " << std::endl;
        // for (const auto& action_name : action_reaction_names.first) std::cout << action_name << std::endl;
         
        // std::cout << "Reaction names: " << std::endl;
        // for (const auto& reaction_name : action_reaction_names.second) std::cout << reaction_name << std::endl;

        // this function also creates vars with create_named_vars, create_input_vars, create_output_vars
        std::cout << "Constructing action-reaction vars and mutex..." << std::flush;
        auto agent_env_mutex_axioms = get_action_reaction_vars(action_reaction_names.first, action_reaction_names.second);
        std::cout << "Done!" << std::endl;

        // std::cout << "Agent LTLf mutex axiom: " << agent_env_mutex_axioms.first << std::endl;
        // std::cout << "Environment mutex axiom: " << agent_env_mutex_axioms.second << std::endl;

        // debug
        // var_mgr_->print_varmgr();
        // print_domain();

        std::cout << "constructing transition function... " << std::flush;
        std::vector<CUDD::BDD> transition_function = get_transition_function(domain_dfa_id, agent_env_mutex_axioms.second);
        std::cout << "Done!" << std::endl;

        std::cout << "constructing final states..." << std::flush;
        CUDD::BDD final_states = get_final_states(domain_dfa_id);
        std::cout << "Done!" << std::endl;

        invariants_bdd_ = var_mgr_->cudd_mgr()->bddOne();
        for (const auto& inv : invariants_)
            invariants_bdd_ = invariants_bdd_ * invariant_to_bdd(domain_dfa_id, inv);
        
        // debug
        // std::cout << invariants_bdd_ << std::endl;

        // construct domain DFA
        SymbolicStateDfa symbolic_dfa(var_mgr_, domain_dfa_id, dfa_initial_state, transition_function, final_states); 

        std::cout << "Constructing and transforming LTLf agent error..." << std::flush; 
        std::string agent_error_formula = get_agent_error_formula(domain_dfa_id, agent_env_mutex_axioms.first);
        ExplicitStateDfaMona agent_error_mona_dfa = ExplicitStateDfaMona::dfa_of_formula(agent_error_formula);
        
        // debug
        // std::cout << "Agent error LTLf formula: " << agent_error_formula << std::endl;
        // std::cout << "Agent error DFA: " << std::endl;
        // agent_error_mona_dfa.dfa_print();

        // transform to symbolic
        ExplicitStateDfa agent_error_dfa = ExplicitStateDfa::from_dfa_mona(var_mgr_, agent_error_mona_dfa);
        SymbolicStateDfa agent_error_sym_dfa = SymbolicStateDfa::from_explicit(agent_error_dfa);
        std::cout << "Done!" << std::endl;
        // agent_error_sym_dfa.dump_dot("agent_error_dfa.dot");

        // adds agent error BDD to invariant
        invariants_bdd_ = invariants_bdd_ * agent_error_sym_dfa.final_states();

        // take product to construct output DFA
        std::cout << "Composition..." << std::flush;
        SymbolicStateDfa domain_dfa = SymbolicStateDfa::product({symbolic_dfa, agent_error_sym_dfa});
        std::cout << "Done!" << std::endl;

        // debug. check correctness of constructed symbolic_dfa
        interactive(domain_dfa);
        // print_domain();

        // return domain_dfa;
        return domain_dfa;
    }

    std::string Domain::get_agent_error_formula(std::size_t automaton_id, const std::string& agent_mutex) const {
        std::string agent_error_formula = agent_mutex;
        std::string pre_formula = "";
        std::unordered_set<std::string> added_action_names;

        // int i = 0; // debug
        for (const auto& act: actions_) {
            std::string action_reaction_name = act.get_action_name();
            // debug 
            // std::cout << "Current action-reaction number: " << i << ". Name: " << action_reaction_name << std::endl;

            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            if (added_action_names.find(action_name) == added_action_names.end()) {
                added_action_names.insert(action_name);

                auto act_pos_pre = act.get_pos_pre();
                auto act_neg_pre = act.get_neg_pre();
                std::string act_pre_props = "";
                for (const auto& i : act_pos_pre) act_pre_props += vars_[i] + " && ";
                for (const auto& i : act_neg_pre) act_pre_props += "!" + vars_[-i] + " && ";

                act_pre_props = "(" + act_pre_props.substr(0, act_pre_props.size() - 4) + ")";
                act_pre_props = "(" + act.get_action_prop() + " -> " + act_pre_props + ")";
                // std::cout << act_pre_props << std::endl;

                pre_formula += act_pre_props + " && ";
            }
            // ++i; debug
        }
        
        pre_formula = "G(" + pre_formula.substr(0, pre_formula.size() - 4) + ")";
        // std::cout << "Agent preconditions LTLf formula: " << pre_formula << std::endl;

        agent_error_formula = agent_error_formula + " && " + pre_formula; 
        return agent_error_formula;
    }

    CUDD::BDD Domain::invariant_to_bdd(std::size_t automaton_id, const Invariant& inv) const {
        CUDD::BDD inv_bdd(var_mgr_->cudd_mgr()->bddOne());
        std::vector<CUDD::BDD> state_vars = var_mgr_->get_state_variables(automaton_id);
        std::unordered_set<int> inv_pos_vars = inv.get_pos_vars();
        std::unordered_set<int> inv_neg_vars = inv.get_neg_vars();

        // mutex for pos vars
        for (const auto& var : inv_pos_vars) {
            CUDD::BDD mutex(var_mgr_->cudd_mgr()->bddOne());
            for (const auto& var_prime : inv_pos_vars)
                if (var_prime != var) mutex = mutex * (!state_vars[var_prime]);
            for (const auto& var_prime_prime : inv_neg_vars) 
                mutex = mutex * state_vars[var_prime_prime];
            inv_bdd = inv_bdd * ((!state_vars[var]) + mutex);
        }

        // mutex for neg vars
        for (const auto& var : inv_neg_vars) {
            CUDD::BDD mutex(var_mgr_->cudd_mgr()->bddOne());
            for (const auto& var_prime : inv_pos_vars)
                mutex = mutex * (!state_vars[var_prime]);
            for (const auto& var_prime_prime: inv_neg_vars)
                if (var_prime_prime != var) mutex = mutex * (state_vars[var_prime_prime]);
            inv_bdd = inv_bdd * ((!state_vars[var]) + mutex);
        }

        // debug
        // std::cout << "Invariant BDD: " << inv_bdd << std::endl;
        return inv_bdd;
    }

    std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> Domain::get_action_reaction_names() const {
        auto action_reaction_names = std::make_pair(std::unordered_set<std::string>(), std::unordered_set<std::string>());

        for (const auto& act: actions_) {
            std::string action_reaction_name = act.get_action_name();

            // finds where action and reaction name splits
            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            action_reaction_names.first.insert(action_name);
            action_reaction_names.second.insert(reaction_name);
        }
        return action_reaction_names;
    }

    std::size_t Domain::get_bits(const std::unordered_set<std::string>& set) const {
        std::size_t count = 0;
        std::size_t size = set.size() - 1;
        while (size) {
            ++count;
            size>>=1; 
        }
        return count;
    }

    std::vector<int> Domain::to_bits(int i, std::size_t size) const {
            std::vector<int> bin;
            if (i == 0) bin.push_back(0);
            else {
                while (i) {
                    int r = i%2;
                    bin.push_back(r);
                    i /= 2;
                }
            }
            while (bin.size() < size) bin.push_back(0);
            return bin;
    }

    std::pair<std::string, CUDD::BDD> Domain::get_action_reaction_vars(const std::unordered_set<std::string>& action_names, const std::unordered_set<std::string>& reaction_names) {

        // create and partition input and output vars
        std::size_t action_bits = get_bits(action_names);
        std::size_t reaction_bits = get_bits(reaction_names);

        // debug
        // std::cout << "Bits for action vars: " << action_bits << std::endl;
        // std::cout << "Bits for reaction vars: " << reaction_bits << std::endl;

        // std::vector<std::string> action_vars;
        // std::vector<std::string> reaction_vars;

        for (int i = 0; i < action_bits; ++i) action_vars_.push_back("a_" + std::to_string(i));
        for (int i = 0; i < reaction_bits; ++i) reaction_vars_.push_back("r_" + std::to_string(i));

        // debug
        // std::cout << "Action vars: ";
        // for (int i = 0; i < action_vars.size(); ++i) {
            // if (i < action_vars.size() - 1) std::cout << action_vars.at(i) + ", ";
            // else std::cout << action_vars.at(i);
        // }
        // std::cout << std::endl;

        // std::cout << "Reaction vars: ";
        // for (int i = 0; i < reaction_vars.size(); ++i) {
            // if (i < reaction_vars.size() - 1) std::cout << reaction_vars.at(i) + ", ";
            // else std::cout << reaction_vars.at(i);
        // }
        // std::cout << std::endl;

        var_mgr_->create_named_variables(action_vars_);
        var_mgr_->create_named_variables(reaction_vars_);

        var_mgr_->create_output_variables(action_vars_);
        var_mgr_->create_input_variables(reaction_vars_);

        // debug
        // var_mgr_->print_varmgr();

        // define encoding for action and reaction vars
        std::unordered_map<std::string, CUDD::BDD> action_name_to_bdd;
        std::unordered_map<std::string, CUDD::BDD> reaction_name_to_bdd;
        std::unordered_map<std::string, std::vector<int>> action_name_to_bin;
        std::unordered_map<std::string, std::vector<int>> reaction_name_to_bin;

        std::unordered_map<std::string, std::string> action_name_to_props;

        // mutual exlcusion axioms for agent and environment
        std::string agent_mutex_prop = "";
        CUDD::BDD env_mutex = var_mgr_->cudd_mgr()->bddZero();

        // encode agent actions and env reactions in binary
        // leftmost bit -> least significant; rightmost bit -> most significant
        int act_int_id = 0, react_int_id = 0;
        for (const auto& action_name : action_names) {
            std::vector<int> act_bin_id = to_bits(act_int_id, action_bits);
            // debug
            // std::cout << "Current action name: " << action_name << ". Action ID: " << act_int_id;
            // std::cout << ". Binary encoding: ";
            // for (const auto& b : act_bin_id) std::cout << b;
            // std::cout << std::endl;
            CUDD::BDD act_bdd = var_mgr_->cudd_mgr()->bddOne();
            std::string act_props = "";
            for (int i = 0; i < act_bin_id.size(); ++i) {
                if (act_bin_id[i] == 1) {
                    if (i == 0) act_props += "a_"+std::to_string(i);
                    else act_props += " && a_"+std::to_string(i);
                    act_bdd = act_bdd * var_mgr_->name_to_variable("a_"+std::to_string(i));
                } else if (act_bin_id[i] == 0) {
                    if (i == 0) act_props += "!a_"+std::to_string(i);
                    else act_props += " && !a_"+std::to_string(i);
                    act_bdd = act_bdd * !(var_mgr_->name_to_variable("a_"+std::to_string(i)));
                }
            }
            act_props = "(" + act_props + ")";
            action_name_to_bdd.insert(std::make_pair(action_name, act_bdd));
            action_name_to_bin.insert(std::make_pair(action_name, act_bin_id));
            action_name_to_props.insert(std::make_pair(action_name, act_props));
            agent_mutex_prop += act_props + " || ";
            id_to_action_name_.insert(std::make_pair(act_int_id, action_name));
            ++act_int_id; 
        }
        
        for (const auto& reaction_name : reaction_names) {
            std::vector<int> react_bin_id = to_bits(react_int_id, reaction_bits);
            CUDD::BDD react_bdd = var_mgr_->cudd_mgr()->bddOne();
            // debug
            // std::cout << "Current reaction name: " << reaction_name;
            // std::cout << ". Binary encoding: ";
            // for (const auto& b : react_bin_id) std::cout << b;
            // std::cout << std::endl;
            for (int i = 0; i < react_bin_id.size(); ++i) {
                if (react_bin_id[i] == 1) react_bdd = react_bdd * var_mgr_->name_to_variable("r_"+std::to_string(i));
                else if (react_bin_id[i] == 0) react_bdd = react_bdd * !(var_mgr_->name_to_variable("r_"+std::to_string(i)));
            }
            reaction_name_to_bdd.insert(std::make_pair(reaction_name, react_bdd));
            reaction_name_to_bin.insert(std::make_pair(reaction_name, react_bin_id));
            env_mutex = env_mutex + react_bdd; // add reaction bdd to mutual exclusion env axiom
            id_to_reaction_name_.insert(std::make_pair(react_int_id, reaction_name));
            ++react_int_id;
        }

        // debug
        // std::cout << "(ACTION NAME: BDD): " << std::endl;
        // for (const auto& pair: action_name_to_bdd) {
            // std::cout << pair.first << ": " << pair.second << std::endl;
        // }

        // std::cout << "(REACTION NAME, BDD): " << std::endl;
        // for (const auto& pair: reaction_name_to_bdd) {
            // std::cout << pair.first << ": " << pair.second << std::endl;
        // }

        // assign encoding to action_reaction_names
        // TODO. this code is a little bit inefficient
        // creates a new set of actions and substitute it
        // with the existing one. Can we avoid it?
        std::unordered_set<Action, ActionHash> updated_actions;
        for (Action act : actions_) {
            // std::cout << "Encoding action: " << act.get_action_name() << std::endl;

            std::string action_reaction_name = act.get_action_name();

            // finds where action and reaction name splits
            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            act.set_agent_bdd(action_name_to_bdd[action_name]);
            act.set_env_bdd(reaction_name_to_bdd[reaction_name]);
            act.set_action_bdd(action_name_to_bdd[action_name] * reaction_name_to_bdd[reaction_name]);

            act.set_agent_prop(action_name_to_props[action_name]);

            // act.set_action_bin(action_name_to_bin[action_name]);
            // act.set_env_bin(reaction_name_to_bin[reaction_name]);

            updated_actions.insert(act);
        }

        actions_ = updated_actions;

        // debug
        // std::cout << "(ACTION-REACTION: BDD)" << std::endl;
        // for (const auto& act: actions_) {
            // std::cout << act.get_action_name() << ": " << act.get_action_bdd() << std::endl; 
        // }

        // debug
        // std::cout << "Agent mutex axiom: " << agent_mutex << std::endl;
        // std::cout << "Environment mutex axiom: " << env_mutex << std::endl;
        
        agent_mutex_prop = "G(" + agent_mutex_prop.substr(0, agent_mutex_prop.size() - 4) + ")";
 
        return std::make_pair(std::string(agent_mutex_prop), CUDD::BDD(env_mutex));
    }

    std::vector<CUDD::BDD> Domain::get_transition_function(std::size_t automaton_id, const CUDD::BDD& env_mutex) const {

        std::vector<CUDD::BDD> transition_function;

        // auxiliar vectors to construct add and delete bdds
        std::vector<CUDD::BDD> add_bdds(vars_.size(), var_mgr_->cudd_mgr()->bddZero());
        std::vector<CUDD::BDD> del_bdds(vars_.size(), var_mgr_->cudd_mgr()->bddZero());

        // assign actions to add and del bdds of vars
        // std::cout << "collecting action-reaction add- and delete-lists..." << std::flush;
        for (const auto& act : actions_) {
            auto act_add_list = act.get_add_list();
            auto act_del_list = act.get_del_list(); 
            for (const auto& id : act_add_list) {
                // debug
                // std::cout << "Action: " << act.get_action_name() << ". Added to var " << id << " BDD add list" << std::endl;
                add_bdds[id] = add_bdds[id] + act.get_action_bdd();
            }
            for (const auto& id : act_del_list) {
                // debug
                // std::cout << "Action: " << act.get_action_name() << ". Added to var " << id << " BDD del list" << std::endl;
                del_bdds[id] = del_bdds[id] + act.get_action_bdd();
            }
        }
        // std::cout << "DONE!" << std::endl;

        // construct bdds in transition function
        for (int i = 0; i < vars_.size(); ++i) {
            CUDD::BDD var_bdd = 
                ((var_mgr_->state_variable(automaton_id, i) * !(del_bdds[i])) +
                (add_bdds[i]));
            transition_function.push_back(var_bdd);
            // debug
            // std::cout << "Variable: " << i << ". BDD: " << var_bdd << std::endl; 
        }

        // construct a Boolean formula that is SAT if and only if
        // environment respects reaction preconditions
        CUDD::BDD env_pre_bdd = get_env_pre(automaton_id);
        
        // environment reaches error state if, and only if:
        // 1. was previously in environment error state; or
        // 2. violated mutex for environment reactions; or
        // 3. violated reaction preconditions
        CUDD::BDD env_err_bdd = (var_mgr_->state_variable(automaton_id, vars_.size())) + (!env_mutex) + (!env_pre_bdd);

        transition_function.push_back(env_err_bdd);

        return transition_function;
    }

    CUDD::BDD Domain::get_agent_pre(std::size_t domain_dfa_id) const {
        CUDD::BDD agent_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
        std::unordered_set<std::string> added_action_names;
        // debug
        // std::cout << "Number of agent-reaction: " << actions_.size() << std::endl;
        // int i = 0;
        for (const auto& act: actions_) {
            std::string action_reaction_name = act.get_action_name();
            // debug 
            // std::cout << "Current action-reaction number: " << i << ". Name: " << action_reaction_name << std::endl;

            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            if (added_action_names.find(action_name) == added_action_names.end()) { // action name has not been added to agent pre
                // debug
                // std::cout << "Action not processed. Adding to preconditions..." << std::flush;

                added_action_names.insert(action_name);

                auto act_pos_pre = act.get_pos_pre();
                auto act_neg_pre = act.get_neg_pre();
                CUDD::BDD act_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
                for (const auto& i : act_pos_pre) act_pre_bdd = act_pre_bdd * var_mgr_->state_variable(domain_dfa_id, i);
                for (const auto& i : act_neg_pre) act_pre_bdd = act_pre_bdd * (!var_mgr_->state_variable(domain_dfa_id, -i));

                act_pre_bdd = ((!act.get_agent_bdd()) + act_pre_bdd);
                agent_pre_bdd = agent_pre_bdd * act_pre_bdd;
                // std::cout << "Done!" << std::endl;

                // var_mgr_-> cudd_mgr() -> ReduceHeap(); // shrinks size of BDDs    
            }
            // auto act_pos_pre = act.get_pos_pre();
            // auto act_neg_pre = act.get_neg_pre();
            // CUDD::BDD act_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
            // for (const auto& i : act_pos_pre) act_pre_bdd = act_pre_bdd * var_mgr_->state_variable(domain_dfa_id, i);
            // for (const auto& i : act_neg_pre) act_pre_bdd = act_pre_bdd * (!var_mgr_->state_variable(domain_dfa_id, -i));
            // act_pre_bdd = ((!act.get_action_bdd()) + act_pre_bdd); // implements function act -> pre(act)
            // act_pre_bdd = ((!act.get_agent_bdd()) + act_pre_bdd);
            // agent_pre_bdd = agent_pre_bdd * act_pre_bdd;
            // ++i;
        }
        return agent_pre_bdd;
    }

    CUDD::BDD Domain::get_env_pre(std::size_t domain_dfa_id) const {
        CUDD::BDD env_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
        std::unordered_map<CUDD::BDD, CUDD::BDD, BDDHash> react_to_legal_acts;

        // for each reaction, gets valid actions
        for (const auto& act : actions_) {
            CUDD::BDD env_bdd = act.get_env_bdd();
            if (react_to_legal_acts.find(env_bdd) == react_to_legal_acts.end())
                react_to_legal_acts.insert(std::make_pair(CUDD::BDD(env_bdd), CUDD::BDD(act.get_agent_bdd())));
            else if (react_to_legal_acts.find(env_bdd) != react_to_legal_acts.end())
                react_to_legal_acts[env_bdd] = react_to_legal_acts[env_bdd] + act.get_agent_bdd();
        }

        // construct env preconditions bdd with results above
        for (const auto& react_act_bdd : react_to_legal_acts) {
            CUDD::BDD react_pre_bdd = ((!(react_act_bdd.first)) + react_act_bdd.second);
            env_pre_bdd = env_pre_bdd * react_pre_bdd;
        }
        return env_pre_bdd;
    }

    CUDD::BDD Domain::get_final_states(std::size_t domain_dfa_id) const {
        CUDD::BDD final_states = var_mgr_->cudd_mgr()->bddOne();
        for (const auto& i : pos_goal_list_) final_states = final_states * var_mgr_->state_variable(domain_dfa_id, i);
        for (const auto& i : neg_goal_list_) final_states = final_states * !(var_mgr_->state_variable(domain_dfa_id, -i));
        // return only final states without agent or error vars
        // agent or error vars are included depending on the game to be solved
        // i.e., adversarial vs. cooperative
        return final_states;
    }

    void Domain::interactive(const SymbolicStateDfa& domain_dfa_) const {
        // keep in mind the order of variables
        // i.e., (F, EnvErr, Act, React, AgErr)
        var_mgr_->print_varmgr();
        print_domain();

        CUDD::BDD agent_error_var = var_mgr_->state_variable(domain_dfa_.automaton_id(), vars_.size()+1);
        CUDD::BDD env_error_var = var_mgr_->state_variable(domain_dfa_.automaton_id(), vars_.size());

        std::vector<int> state = domain_dfa_.initial_state(); // (F, EnvErr, AgErr)
        std::vector<CUDD::BDD> transition_function = domain_dfa_.transition_function();
        CUDD::BDD final_states = domain_dfa_.final_states();

        std::cout << "Planning domain interactive debug" << std::endl;

        std::cout << "Agent actions: " << std::endl;
        for (const auto& id_to_act : id_to_action_name_)
            std::cout << "ID: " << id_to_act.first << ". Action: " << id_to_act.second << std::endl;
        std::cout << std::endl;

        std::cout << "Environment reactions: " << std::endl;
        for (const auto& id_to_react : id_to_reaction_name_) 
            std::cout << "ID: " << id_to_react.first << ". Reaction: " << id_to_react.second << std::endl;
        std::cout << std::endl;
        
        while (true) {
            std::cout << "State vector: ";
            for (const auto& v : state) std::cout << v;
            std::cout << std::endl;
            std::string string_state = "{";
            for (int i = 0; i < vars_.size(); ++i)
                if (state[i] == 1) string_state += vars_[i] + ", ";
            string_state = string_state.substr(0, string_state.size() - 2) + "}";
            std::cout << "State vars: " << string_state << std::endl; 
            
            std::vector<int> state_prime(state.begin(), state.begin() + state.size() - 1);
            for (int i = 0; i < var_mgr_->output_variable_count(); ++i) state_prime.push_back(0);
            for (int i = 0; i < var_mgr_->input_variable_count(); ++i) state_prime.push_back(0);
            state_prime.push_back(state[state.size() - 1]);
            std::cout << "The current state is: ";
            if (agent_error_var.Eval(state_prime.data()).IsOne())
                std::cout << "- AGENT ERROR STATE -";
            if (env_error_var.Eval(state_prime.data()).IsOne())
                std::cout << "- ENVIRONMENT ERROR STATE -";
            if (final_states.Eval(state_prime.data()).IsOne()) std::cout << "- FINAL -";
            else std::cout << "- NOT FINAL -";
            std::cout << std::endl;
            
            std::vector<int> transition(state.begin(), state.begin() + state.size() - 1); // (F, EnvErr)

            std::cout << "Insert ID of agent action: ";
            int act_id;
            std::cin >> act_id;
            for (const auto& b : to_bits(act_id, var_mgr_->output_variable_count())) transition.push_back(b);

            std::cout << "Insert ID of environment reaction: ";
            int react_id;
            std::cin >> react_id;
            for (const auto& b : to_bits(react_id, var_mgr_->input_variable_count())) transition.push_back(b);

            transition.push_back(state[state.size() - 1]);

            std::cout << "Input to transition function: ";
            for (const auto& v : transition) std::cout << v;
            std::cout << std::endl;

            std::vector<int> new_state;
            for (int i = 0; i < transition_function.size(); ++i) {
                // std::cout << "Var: " << i << ". Next evaluation: " << transition_function[i].Eval(transition.data()).IsOne() << std::endl;
                new_state.push_back(transition_function[i].Eval(transition.data()).IsOne());
            }
            state = new_state;
        }
        return;
    }

    void Domain::print_domain() const {
        std::cout << "############ PLANNING DOMAIN #############" << std::endl;

        std::cout << "Domain variables: " << std::endl;
        for (int i = 0; i < vars_.size(); ++i) std::cout << i << ": " << vars_.at(i) << std::endl;
        std::cout << std::endl;

        std::cout << "Initial state: " << std::endl;
        for (auto const& i : init_state_) std::cout << i;
        std::cout << std::endl;

        std::cout << "Goal: " << std::endl;
        std::string goal_list = "{";
        for (auto const& i: pos_goal_list_) goal_list = goal_list + std::to_string(i) + ", ";
        for (auto const& i: neg_goal_list_) goal_list = goal_list + std::to_string(i) + ", ";
        std::cout << goal_list.substr(0, goal_list.size() - 2) << "}" << std::endl;

        std::cout << std::endl;

        std::cout << "Number of action-reaction pairs: " << actions_.size() << std::endl;
        std::cout << std::endl;
        for (auto const& act : actions_) {act.print(); std::cout << std::endl;}

        std::cout << "Number of invariants: " << invariants_.size() << std::endl;
        std::cout << std::endl;
        for (auto const& inv : invariants_) {inv.print(); std::cout << std::endl;}

        std::cout << "##########################################" << std::endl;
    }
}