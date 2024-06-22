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
        std::string translate_command = "./../../submodules/translate.py 0 " + domain_pddl + " " + problem_pddl;
        system(translate_command.c_str());

        // read output.sas to generate data members
        parse_sas(); 

        // generate invariants in three files
        // 1. predicate file
        // 2. objects file
        // 3. invariants file
        std::string invariants_command = "./../../submodules/invariant_finder.py " + domain_pddl + " " + problem_pddl;
        system(invariants_command.c_str());

        // debug
        // for (const auto& p : var_to_id) std::cout << "Var: " << p.first << ". ID: " << p.second << std::endl; 

        // generate grounded_invs file
        std::string ground_invariants_command = "./../../submodules/invariant_grounder.py";
        system(ground_invariants_command.c_str());

        // grounds invariants
        // auxiliary data structure
        std::unordered_map<std::string, int> var_to_id;
        for (int i = 0; i < vars_.size(); ++i) var_to_id.insert(std::make_pair(vars_[i], i));

        std::ifstream inv_input_stream("grounded_invs.txt");
        std::string inv_line;
        while (std::getline(inv_input_stream, inv_line)) {
            boost::replace_all(inv_line, "(", "_");
            boost::replace_all(inv_line, ")", "_");
            boost::replace_all(inv_line, " ", "");
            boost::replace_all(inv_line, ",", "_");
            boost::replace_all(inv_line, "-", "_");
            boost::to_lower(inv_line);
            // std::cout << inv_line << std::endl;
            std::vector<std::string> inv_vec;
            boost::split(inv_vec, inv_line, boost::is_any_of(";"));
            for (auto& atom : inv_vec) boost::trim_if(atom, boost::is_any_of("_"));

            // debug
            // std::cout << "Invariant: " << std::flush;
            // for (const auto& atom : inv_vec) std::cout << atom << " " << std::flush;
            // std::cout << std::endl;

            auto inv_vars = get_invariant_vars(inv_vec, var_to_id);
            Invariant inv(inv_vars.first, inv_vars.second);
            add_invariant(inv);
        }
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

    SymbolicStateDfa Domain::to_ltlf_and_symbolic() {
        var_mgr_->cudd_mgr() -> AutodynEnable();

        std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> action_reaction_names 
            = get_action_reaction_names();

        std::pair<std::string, std::string> agent_env_mutex_axioms = get_ltlf_action_reaction_vars(action_reaction_names.first, action_reaction_names.second);

        // debug
        // print_domain();
        // std::cout << "LTLf agent mutex axiom: " << agent_env_mutex_axioms.first << std::endl;
        // std::cout << "LTLf env mutex axiom: " << agent_env_mutex_axioms.second << std::endl;

        // std::cout << "Transforming to LTLf and symbolic DFA..." << std::flush;
        std::string ltlf_init = get_ltlf_init(); // gets initial state
        std::string ltlf_trans = get_ltlf_transition_function(agent_env_mutex_axioms.first, agent_env_mutex_axioms.second); // gets frame axiom
        std::string ltlf_goal = get_ltlf_goal(); // gets goal

        // debug
        // std::cout << "Initial state formula: " << ltlf_init << std::endl;
        // std::cout << "Goal formula: " << ltlf_goal << std::endl;
        // std::cout << "Transition function formula: " << ltlf_trans << std::endl;

        std::string pddl_ltlf = "(((" + ltlf_init + ") && (" + ltlf_trans + ")) -> " + "(" + ltlf_goal + "))";    


        // debug
        // ExplicitStateDfaMona init_state_dfa = ExplicitStateDfaMona::dfa_of_formula(ltlf_init);
        // init_state_dfa.dfa_print();
        // ExplicitStateDfaMona ltlf_goal_dfa = ExplicitStateDfaMona::dfa_of_formula(ltlf_goal);
        // ltlf_goal_dfa.dfa_print();
        // ExplicitStateDfaMona ltlf_trans_dfa = ExplicitStateDfaMona::dfa_of_formula(ltlf_trans);
        // ltlf_trans_dfa.dfa_print();
    
        ExplicitStateDfaMona mona_dfa = ExplicitStateDfaMona::dfa_of_formula(pddl_ltlf);

        // debug
        mona_dfa.dfa_print();

        ExplicitStateDfa explicit_dfa = ExplicitStateDfa::from_dfa_mona(var_mgr_, mona_dfa);
        SymbolicStateDfa domain_dfa = SymbolicStateDfa::from_explicit(explicit_dfa);

        // std::cout << "Done!" << std::endl;

        return domain_dfa;
    }

    std::pair<std::string, std::string> Domain::get_ltlf_action_reaction_vars(const std::unordered_set<std::string>& action_names, const std::unordered_set<std::string>& reaction_names) {
        // create and partition input and output vars
        std::size_t action_bits = get_bits(action_names);
        std::size_t reaction_bits = get_bits(reaction_names);

        for (int i = 0; i < action_bits; ++i) action_vars_.push_back("a_" + std::to_string(i));
        for (int i = 0; i < reaction_bits; ++i) reaction_vars_.push_back("r_" + std::to_string(i));

        std::vector<std::string> domain_vars = vars_;
        domain_vars.push_back("ag_err");
        domain_vars.push_back("env_err");

        var_mgr_->create_named_variables(action_vars_);
        var_mgr_->create_named_variables(reaction_vars_);
        var_mgr_->create_named_variables(domain_vars);

        var_mgr_->create_output_variables(action_vars_);
        var_mgr_->create_input_variables(reaction_vars_);
        var_mgr_->create_input_variables(domain_vars);

        // define encoding for action and reaction vars
        std::unordered_map<std::string, std::string> action_name_to_ltlf;
        std::unordered_map<std::string, std::string> reaction_name_to_ltlf;
    
        std::string agent_ltlf_mutex = "";
        std::string env_ltlf_mutex = "";

        int act_int_id = 0, react_int_id = 0;
        for (const auto& action_name : action_names) {
            std::vector<int> act_bin_id = to_bits(act_int_id, action_bits);
            std::string act_ltlf = "";
            for (int i = 0; i < act_bin_id.size(); ++i) {
                if (act_bin_id[i] == 1) act_ltlf += "a_" + std::to_string(i) + " && ";
                else if (act_bin_id[i] == 0) act_ltlf += "!a_" + std::to_string(i) + " && ";
            }
            act_ltlf = "(" + act_ltlf.substr(0, act_ltlf.size()-4) + ")";
            action_name_to_ltlf.insert(std::make_pair(action_name, act_ltlf));
            agent_ltlf_mutex += act_ltlf + " || "; 
            id_to_action_name_.insert(std::make_pair(act_int_id, action_name));
            ++act_int_id; 
        }
        agent_ltlf_mutex = agent_ltlf_mutex.substr(0, agent_ltlf_mutex.size() - 4);
        agent_ltlf_mutex = "(" + agent_ltlf_mutex + ")";
        
        for (const auto& reaction_name : reaction_names) {
            std::vector<int> react_bin_id = to_bits(react_int_id, reaction_bits);
            std::string react_ltlf = "";
            for (int i = 0; i < react_bin_id.size(); ++i) {
                if (react_bin_id[i] == 1) react_ltlf += "r_"+std::to_string(i) + " && ";
                else if (react_bin_id[i] == 0) react_ltlf += "!r_"+std::to_string(i) + " && ";
            }
            react_ltlf = "(" + react_ltlf.substr(0, react_ltlf.size() -4) + ")";
            reaction_name_to_ltlf.insert(std::make_pair(reaction_name, react_ltlf));
            env_ltlf_mutex += react_ltlf + " || ";
            id_to_reaction_name_.insert(std::make_pair(react_int_id, reaction_name));
            ++react_int_id;
        }
        env_ltlf_mutex = env_ltlf_mutex.substr(0, env_ltlf_mutex.size() - 4);
        env_ltlf_mutex = "(" + env_ltlf_mutex + ")";


        std::unordered_set<Action, ActionHash> updated_actions;
        for (Action act : actions_) {
            // std::cout << "Encoding action: " << act.get_action_name() << std::endl;

            std::string action_reaction_name = act.get_action_name();

            // finds where action and reaction name splits
            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            act.set_agent_ltlf(action_name_to_ltlf[action_name]);
            act.set_env_ltlf(reaction_name_to_ltlf[reaction_name]);
            act.set_action_ltlf("(" + action_name_to_ltlf[action_name] + " && " + reaction_name_to_ltlf[reaction_name] + ")");

            // act.set_action_bin(action_name_to_bin[action_name]);
            // act.set_env_bin(reaction_name_to_bin[reaction_name]);

            updated_actions.insert(act);
        }

        actions_ = updated_actions;

        return std::make_pair(std::string(agent_ltlf_mutex), std::string(env_ltlf_mutex));
    }

    std::string Domain::get_ltlf_init() const {
        std::string init = "";
        for (int i = 0; i < init_state_.size(); ++i) {
            if (init_state_[i] == 1) init += vars_[i] + " && ";
            else if (init_state_[i] == 0) init += "!" + vars_[i] + " && ";
        }
        init += "!ag_err && !env_err";
        return "(" + init + ")";
    }

    std::string Domain::get_ltlf_goal() const {
        std::string goal = "";
        for (const auto& i : pos_goal_list_) goal += vars_[i]+ " && ";
        for (const auto& i : neg_goal_list_) goal += "!" + vars_[i] + " && ";
        goal = "(F(" + goal.substr(0, goal.size() - 4) + "))";
        goal = "(G(!ag_err) && (F(env_err) || " + goal + "))";
        return goal;
    }

    std::string Domain::get_ltlf_transition_function(const std::string& ltlf_agent_mutex, const std::string& ltlf_env_mutex) const {

        std::string transition_function = "";

        // auxiliar vectors to construct add and delete ltlf
        std::vector<std::string> add_ltlf(vars_.size(), "");
        std::vector<std::string> del_ltlf(vars_.size(), "");

        for (const auto& act : actions_) {
            auto act_add_list = act.get_add_list();
            auto act_del_list = act.get_del_list(); 
            for (const auto& id : act_add_list) {
                // debug
                // std::cout << "Action: " << act.get_action_name() << ". Added to var " << vars_[id] << " LTLf add list" << std::endl;
                add_ltlf[id] = add_ltlf[id] + "(" + act.get_action_ltlf() + ") || ";
            }
            for (const auto& id : act_del_list) {
                // debug
                // std::cout << "Action: " << act.get_action_name() << ". Added to var " << vars_[id] << " LTLf del list" << std::endl;
                del_ltlf[id] = del_ltlf[id] + "(" + act.get_action_ltlf() + ") || ";
            }
        }
        for (int i = 0; i < add_ltlf.size(); ++i) {
            if (add_ltlf[i] == "") add_ltlf[i] = "(false)";
            else add_ltlf[i] = "(" + add_ltlf[i].substr(0, add_ltlf[i].size()-4) + ")";
        }
        for (int i = 0; i < del_ltlf.size(); ++i) {
            if (del_ltlf[i] == "") del_ltlf[i] = "(false)";
            else del_ltlf[i] = "(" + del_ltlf[i].substr(0, del_ltlf[i].size()-4) + ")";
        }

        // construct bdds in transition function
        // std::cout << "constructing BDDs of vars in transition function... " << std::flush;
        for (int i = 0; i < vars_.size(); ++i) {
            std::string var_ltlf_transition = "(X(" + vars_[i] + ") <-> ((" + vars_[i] + " && !" + del_ltlf[i] + ") || (" + add_ltlf[i] + ")))";  
            transition_function += var_ltlf_transition + " && ";
            // debug
            // std::cout << "Variable: " << vars_[i] << ". LTLf frame axiom: " << var_ltlf_transition << std::endl; 
        }

        std::string agent_pre_ltlf = get_ltlf_agent_pre();
        std::string env_pre_ltlf = get_ltlf_env_pre();

        // debug
        // std::cout << "Agent LTLf precondition formula: " << agent_pre_ltlf << std::endl;
        // std::cout << "Environment LTLf precondition formula: " << env_pre_ltlf << std::endl;

        std::string agent_error_trans = "(X(ag_err) <-> (ag_err || (!" + ltlf_agent_mutex + ") || (!" + agent_pre_ltlf + ")))";
        std::string env_error_trans = "(X(env_err) <-> (env_err || (!" + ltlf_env_mutex + ") || (!" + env_pre_ltlf + ")))";

        transition_function = "X(G(" + transition_function + agent_error_trans + " && " + env_error_trans + "))";

        return transition_function;
    }

    std::string Domain::get_ltlf_agent_pre() const {
        std::string agent_pre_ltlf = "";
        std::unordered_set<std::string> added_action_names;
        // debug
        // std::cout << "Number of agent-reaction: " << actions_.size() << std::endl;
        for (const auto& act: actions_) {
            std::string action_reaction_name = act.get_action_name();

            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            if (added_action_names.find(action_name) == added_action_names.end()) { // action name has not been added to agent pre
                added_action_names.insert(action_name);

                auto act_pos_pre = act.get_pos_pre();
                auto act_neg_pre = act.get_neg_pre();
                std::string act_pre_ltlf = "";
                for (const auto& i : act_pos_pre) act_pre_ltlf += vars_[i] + " && ";
                for (const auto& i : act_neg_pre) act_pre_ltlf += "!" + vars_[-i] + " && ";
                if (act_pre_ltlf == "") act_pre_ltlf = "(true)";
                else act_pre_ltlf = "(" + act_pre_ltlf.substr(0, act_pre_ltlf.size()-4) + ")";

                act_pre_ltlf = "(" + act.get_agent_ltlf() + " -> " + act_pre_ltlf + ")";
                agent_pre_ltlf += act_pre_ltlf + " && ";
            }
        }
        if (agent_pre_ltlf == "") return "true";
        else return "(" + agent_pre_ltlf.substr(0, agent_pre_ltlf.size() -4) + ")"; 
    }

    std::string Domain::get_ltlf_env_pre() const {
        std::string env_pre_ltlf = "";
        std::unordered_map<std::string, std::string> react_to_legal_acts;

        // for each reaction, gets valid actions
        for (const auto& act : actions_) {
            std::string env_ltlf = act.get_env_ltlf();
            if (react_to_legal_acts.find(env_ltlf) == react_to_legal_acts.end())
                react_to_legal_acts.insert(std::make_pair(std::string(env_ltlf), std::string(act.get_agent_ltlf() + " || ")));
            else if (react_to_legal_acts.find(env_ltlf) != react_to_legal_acts.end())
                react_to_legal_acts[env_ltlf] += act.get_agent_ltlf() + " || ";
        }

        for (auto& react : react_to_legal_acts) 
            react_to_legal_acts[react.first] = "(" + react_to_legal_acts[react.first].substr(0, react_to_legal_acts[react.first].size() - 4) + ")";

        // construct env preconditions bdd with results above
        for (const auto& react_act_ltlf : react_to_legal_acts) {
            std::string react_pre_ltlf = "((" + react_act_ltlf.first + ") -> (" + react_act_ltlf.second + "))" ;
            env_pre_ltlf += react_pre_ltlf + " && "; 
        }
        
        env_pre_ltlf = "(" + env_pre_ltlf.substr(0, env_pre_ltlf.size() - 4) + ")";
        return env_pre_ltlf;   
    }
    
    SymbolicStateDfa Domain::to_symbolic() {
        // Remember the order of variables
        // (vars, act, react).

        // enable dynamic reordering for improving performance
        var_mgr_->cudd_mgr() -> AutodynEnable();

        // construct state vars of domain symbolic dfa
        // vars_.size() are vars, with indexes from 0 to vars_.size() - 1;
        // 2 are agent- and environment-error vars
        // state var at index vars_.size() is agent-error var
        // state var at index vars_.size() + 1 is env-error var 
        std::size_t domain_dfa_id = var_mgr_-> create_state_variables(vars_.size() + 2);
        // std::vector<std::string> domain_dfa_vars = vars_;
        // domain_dfa_vars.push_back("ag_err");
        // domain_dfa_vars.push_back("env_err");
        // std::size_t domain_dfa_id = var_mgr_->create_named_state_variables(domain_dfa_vars);
        

        // DFA initial state is as domain's
        // plus two 0's denoting that
        // error vars are false in DFA initial state
        std::vector<int> dfa_initial_state = init_state_;
        dfa_initial_state.push_back(0);
        dfa_initial_state.push_back(0);

        // define input and output vars
        // store them in var_mgr_. Use create_named_vars, create_input_vars, create_output_vars
        // assign them to actions (as conjunctions of BDDs)
        std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> action_reaction_names 
            = get_action_reaction_names();

        // debug
        // std::cout << "Action names: " << std::endl;
        // for (const auto& action_name : action_reaction_names.first) std::cout << action_name << std::endl;
         
        // std::cout << "Reaction names: " << std::endl;
        // for (const auto& reaction_name : action_reaction_names.second) std::cout << reaction_name << std::endl;

        // this function also creates vars with create_named_vars, create_input_vars, create_output_vars
        auto agent_env_mutex_axioms = get_action_reaction_vars(action_reaction_names.first, action_reaction_names.second);

        // debug
        // var_mgr_->print_varmgr();
        std::vector<CUDD::BDD> transition_function = get_transition_function(domain_dfa_id, agent_env_mutex_axioms.first, agent_env_mutex_axioms.second);

        CUDD::BDD final_states = get_final_states(domain_dfa_id);

        invariants_bdd_ = var_mgr_->cudd_mgr()->bddOne();
        for (const auto& inv : invariants_)
            invariants_bdd_ = invariants_bdd_ * invariant_to_bdd(domain_dfa_id, inv);

        // debug
        // std::cout << invariants_bdd_ << std::endl;

        // construct output object
        SymbolicStateDfa symbolic_dfa(var_mgr_, domain_dfa_id, dfa_initial_state, transition_function, final_states); 
        // symbolic_dfa.dump_dot("domain_dfa.dot");

        // debug. check correctness of constructed symbolic_dfa
        // interactive(symbolic_dfa);
        // print_domain();

        return symbolic_dfa;
    }

    std::pair<std::unordered_set<int>, std::unordered_set<int>> Domain::get_invariant_vars(const std::vector<std::string>& inv_vec, const std::unordered_map<std::string, int>& var_to_id) const {
        std::pair<std::unordered_set<int>, std::unordered_set<int>> vars;
        std::unordered_set<int> pos_vars;
        std::unordered_set<int> neg_vars;
        for (const auto& var: inv_vec) {
            if (std::find(vars_.begin(), vars_.end(), var) != vars_.end()) {
                if (boost::starts_with(var, "!")) neg_vars.insert(var_to_id.at(var));
                else pos_vars.insert(var_to_id.at(var));
            }
        }
        vars.first = pos_vars;
        vars.second = neg_vars;
        return vars;
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
        if (size == 0) return 1;
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

    std::pair<CUDD::BDD, CUDD::BDD> Domain::get_action_reaction_vars(const std::unordered_set<std::string>& action_names, const std::unordered_set<std::string>& reaction_names) {

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
        // std::unordered_map<std::string, std::vector<int>> action_name_to_bin;
        // std::unordered_map<std::string, std::vector<int>> reaction_name_to_bin;

        // mutual exlcusion axioms for agent and environment
        CUDD::BDD agent_mutex = var_mgr_->cudd_mgr()->bddZero();
        CUDD::BDD env_mutex = var_mgr_->cudd_mgr()->bddZero();

        // encode agent actions and env reactions in binary
        // leftmost bit -> least significant; rightmost bit -> most significant
        // std::cout << "encoding agent acts..." << std::flush;
        int act_int_id = 0, react_int_id = 0;
        for (const auto& action_name : action_names) {
            std::vector<int> act_bin_id = to_bits(act_int_id, action_bits);
            // debug
            // std::cout << "Current action name: " << action_name << ". Action ID: " << act_int_id;
            // std::cout << ". Binary encoding: ";
            // for (const auto& b : act_bin_id) std::cout << b;
            // std::cout << std::endl;
            CUDD::BDD act_bdd = var_mgr_->cudd_mgr()->bddOne();
            for (int i = 0; i < act_bin_id.size(); ++i) {
                if (act_bin_id[i] == 1) act_bdd = act_bdd * var_mgr_->name_to_variable("a_"+std::to_string(i));
                else if (act_bin_id[i] == 0) act_bdd = act_bdd * !(var_mgr_->name_to_variable("a_"+std::to_string(i)));
            }
            action_name_to_bdd.insert(std::make_pair(action_name, act_bdd));
            // action_name_to_bin.insert(std::make_pair(action_name, act_bin_id));
            agent_mutex = agent_mutex + act_bdd; // add action bdd to mutual exclusion agent axiom
            id_to_action_name_.insert(std::make_pair(act_int_id, action_name));
            ++act_int_id; 
        }
        // std::cout << "Done!" << std::flush;

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
            // reaction_name_to_bin.insert(std::make_pair(reaction_name, react_bin_id));
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
 
        return std::make_pair(CUDD::BDD(agent_mutex), CUDD::BDD(env_mutex));
    }

    std::vector<CUDD::BDD> Domain::get_transition_function(std::size_t automaton_id, const CUDD::BDD& agent_mutex, const CUDD::BDD& env_mutex) const {

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
        // std::cout << "constructing BDDs of vars in transition function... " << std::flush;
        for (int i = 0; i < vars_.size(); ++i) {
            CUDD::BDD var_bdd = 
                ((var_mgr_->state_variable(automaton_id, i) * !(del_bdds[i])) +
                (add_bdds[i]));
            transition_function.push_back(var_bdd);
            // debug
            // std::cout << "Variable: " << i << ". BDD: " << var_bdd << std::endl; 
        }
        // std::cout << "DONE!" << std::endl;

        // debug
        // std::cout << "Agent mutex BDD: " << agent_mutex << std::endl;
        // std::cout << "Env mutex BDD: " << env_mutex << std::endl;

        // construct a Boolean formula that is SAT if and only if
        // agent (resp. env) respects action (resp. reaction) preconditions
        // std::cout << "Computing agent error BDD... " << std::flush;
        CUDD::BDD agent_pre_bdd = get_agent_pre(automaton_id);
        // std::cout << "DONE!" << std::endl;
        // std::cout << "Computing environment error BDD..." << std::flush;
        CUDD::BDD env_pre_bdd = get_env_pre(automaton_id);
        // std::cout << "DONE!" << std::endl;
        
        
        // agent reaches error state if, and only if:
        // 1. was previously in agent error state; or
        // 2. violated mutex for agent actions; or
        // 3. violated action preconditions
        CUDD::BDD agent_err_bdd = (var_mgr_->state_variable(automaton_id, vars_.size()))  + (!agent_mutex) + (!agent_pre_bdd);
        // environment reaches error state if, and only if:
        // 1. was previously in environment error state; or
        // 2. violated mutex for environment reactions; or
        // 3. violated reaction preconditions
        CUDD::BDD env_err_bdd = (var_mgr_->state_variable(automaton_id, vars_.size() + 1)) + (!env_mutex) + (!env_pre_bdd);
    
        transition_function.push_back(agent_err_bdd);
        transition_function.push_back(env_err_bdd);

        return transition_function;
    }

    CUDD::BDD Domain::get_agent_pre(std::size_t domain_dfa_id) const {
        CUDD::BDD agent_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
        std::unordered_set<std::string> added_action_names;
        // debug
        // std::cout << "Number of agent-reaction: " << actions_.size() << std::endl;
        int i = 0;
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
            ++i;
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
        // i.e., (F, Act, React)
        // var_mgr_->print_varmgr();
        print_domain();

        std::vector<int> state = domain_dfa_.initial_state();
        std::vector<CUDD::BDD> transition_function = domain_dfa_.transition_function();
        CUDD::BDD final_states = domain_dfa_.final_states();

        std::cout << "[pddl2dfa] Planning domain interactive debug" << std::endl;

        std::cout << "[pddl2dfa] Agent actions: " << std::endl;
        for (const auto& id_to_act : id_to_action_name_)
            std::cout << "ID: " << id_to_act.first << ". Action: " << id_to_act.second << std::endl;
        std::cout << std::endl;

        std::cout << "[pddl2dfa] Environment reactions: " << std::endl;
        for (const auto& id_to_react : id_to_reaction_name_) 
            std::cout << "ID: " << id_to_react.first << ". Reaction: " << id_to_react.second << std::endl;
        std::cout << std::endl;
        
        while (true) {
            std::cout << "[pddl2dfa] State vector: ";
            for (const auto& v : state) std::cout << v;
            std::cout << std::endl;
            std::string string_state = "{";
            for (int i = 0; i < vars_.size(); ++i)
                if (state[i] == 1) string_state += vars_[i] + ", ";
            string_state = string_state.substr(0, string_state.size() - 2) + "}";
            std::cout << "[pddl2dfa] State vars: " << string_state << std::endl; 
            

            std::cout << "[pddl2dfa] The current state is: ";
            if (var_mgr_->state_variable(domain_dfa_.automaton_id(), vars_.size()).Eval(state.data()).IsOne())
                std::cout << "- AGENT ERROR STATE -";
            if (var_mgr_->state_variable(domain_dfa_.automaton_id(), vars_.size()+1).Eval(state.data()).IsOne())
                std::cout << "- ENVIRONMENT ERROR STATE -";
            if (final_states.Eval(state.data()).IsOne()) std::cout << "- FINAL -";
            else std::cout << "- NOT FINAL -";
            std::cout << std::endl;
            
            std::vector<int> transition = state;

            // std::cout << "Insert encoding of agent action (whitespace separated): ";
            // for (int i = 0; i < var_mgr_->output_variable_count(); ++i) {
                // int j; // user input (binary)
                // std::cin >> j;
                // transition.push_back(j);
            // }

            // std::cout << "Insert encoding of environment reaction (whitespace separated): ";
            // for (int i = 0; i < var_mgr_->input_variable_count(); ++i) {
                // int j; // user input (binary)
                // std::cin >> j;
                // transition.push_back(j);
            // }

            std::cout << "[pddl2dfa] Insert ID of agent action: ";
            int act_id;
            std::cin >> act_id;
            for (const auto& b : to_bits(act_id, var_mgr_->output_variable_count())) transition.push_back(b);

            std::cout << "[pddl2dfa] Insert ID of environment reaction: ";
            int react_id;
            std::cin >> react_id;
            for (const auto& b : to_bits(react_id, var_mgr_->input_variable_count())) transition.push_back(b);

            std::cout << "[pddl2dfa] Input to transition function: ";
            for (const auto& v : transition) std::cout << v;
            std::cout << std::endl;

            std::vector<int> new_state;
            for (int i = 0; i < transition_function.size(); ++i) {
                // std::cout << "Var: " << i << ". Next evaluation: " << transition_function[i].Eval(transition.data()).IsOne() << std::endl;
                new_state.push_back(transition_function[i].Eval(transition.data()).IsOne());
            }
            state = new_state;
            std::cout << std::endl;
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