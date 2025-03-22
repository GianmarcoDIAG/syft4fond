//
// Created by antonio on 2/5/25.
//

#include "LTLfFONDDomain.h"

namespace Syft {
    LTLfFONDDomain::LTLfFONDDomain(
        std::shared_ptr<VarMgr> var_mgr,
        const std::string& domain_file,
        const std::string& init_file,
        const std::string& goal_file
    ) : var_mgr_(var_mgr), domain_file_(domain_file), init_file_(init_file), goal_file_(goal_file) {}

    void LTLfFONDDomain::parse_sas() {
            std::ifstream sas_input_stream("output.sas");
            std::string line;
            while (std::getline(sas_input_stream, line)) {
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
                    // adds nop dummy action
                    Action nop("nop_REACT_0", {}, {}, {}, {});
                    actions_.insert(nop);

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
                        } else if (boost::starts_with(line, "  ")) {
                            boost::trim(line);
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
        }

    SynthesisResult LTLfFONDDomain::run(bool is_interactive) {
        // 1. construct DFA of planning domain
        std::cout << "[syft4fond_thesis] Transforming PDDL into DFA...";
        // Define and start the stopwatch
        Stopwatch pddl2dfa;
        pddl2dfa.start();

        // Create the domain and do the effective construction
        Domain domain(var_mgr_, domain_file_, init_file_);
        //domain.print_domain();
        SymbolicStateDfa domain_sdfa = domain.to_symbolic();

        auto pddl2dfa_t = pddl2dfa.stop().count() / 1000.0;
        running_times_.push_back(pddl2dfa_t);
        std::cout << "Done [" << pddl2dfa_t << " s]" << std::endl;

        // 2. construct DFA of LTLf formula
        // i. read LTLf goal from file
        std::cout << "[syft4fond_thesis] Transforming LTLf goal into DFA..." << std::flush;
        Stopwatch ltlf2dfa;
        ltlf2dfa.start();

        // Open the file and scan wach row
        std::ifstream ltlf_stream(goal_file_);
        std::string ltlf_goal;
        std::getline(ltlf_stream, ltlf_goal);

        // ii. parse LTLf goal
        // Passing the same domain as before
        ltlf_goal = parse_goal(domain, ltlf_goal);

        // iii. LTLf -> DFA
        ExplicitStateDfaMona goal_mona_dfa = ExplicitStateDfaMona::dfa_of_formula(ltlf_goal);
        ExplicitStateDfa goal_dfa = ExplicitStateDfa::from_dfa_mona(var_mgr_, goal_mona_dfa);
        SymbolicStateDfa goal_sdfa = SymbolicStateDfa::from_explicit(goal_dfa);

        auto ltlf2dfa_t = ltlf2dfa.stop().count() / 1000.0;
        running_times_.push_back(ltlf2dfa_t);
        std::cout << "Done [" <<  ltlf2dfa_t << " s]" << std::endl;

        // 3. solve game
        std::cout << "[syft4fond_thesis] Synthesisizing a strategy..." << std::flush;
        Stopwatch synthesis;
        synthesis.start();

        std::vector<SymbolicStateDfa> game_sdfas = {domain_sdfa, goal_sdfa};
        //Do the product
        SymbolicStateDfa dfa_game = SymbolicStateDfa::domain_compose(game_sdfas);
        CUDD::BDD invariant_bdd = domain.get_invariants_bdd();

        CoOperativeReachabilitySynthesizer synthesizer(
            dfa_game,
            Player::Agent,
            Player::Environment,
            dfa_game.final_states(),
            invariant_bdd
        );
        SynthesisResult result = synthesizer.run();
        auto synthesis_t = synthesis.stop().count() / 1000.0;
        running_times_.push_back(synthesis_t);
        Syft::MaxSet maxSet = synthesizer.AbstractMaxSet(std::move(result));
        std::cout << "Done [" << synthesis_t << " s]" <<  std::endl;

        if(is_interactive) interactive(domain, dfa_game, maxSet);

        return result;
    }

    std::vector<int> LTLfFONDDomain::to_bits(int i, std::size_t size) const {
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

    SymbolicStateDfa LTLfFONDDomain::to_symbolic() {
        // Remember the order of variables
        // (vars, act, react).

        // enable dynamic reordering for improving performance
        // var_mgr_->cudd_mgr() -> AutodynEnable();

        // construct state vars of domain symbolic dfa
        // vars_.size() are vars, with indexes from 0 to vars_.size() - 1;
        // 2 are agent- and environment-error vars
        // state var at index vars_.size() is agent-error var
        // state var at index vars_.size() + 1 is env-error var
        // std::size_t domain_dfa_id = var_mgr_-> create_state_variables(vars_.size() + 2);
        std::vector<std::string> domain_dfa_vars = vars_;
        domain_dfa_vars.push_back("ag_err");
        domain_dfa_vars.push_back("env_err");
        std::size_t domain_dfa_id = var_mgr_->create_named_state_variables(domain_dfa_vars);


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

        // this function also creates vars with create_named_vars, create_input_vars, create_output_vars
        auto agent_env_mutex_axioms = get_action_reaction_vars(action_reaction_names.first, action_reaction_names.second);

        std::vector<CUDD::BDD> transition_function = get_transition_function(domain_dfa_id, agent_env_mutex_axioms.first, agent_env_mutex_axioms.second);

        CUDD::BDD final_states = get_final_states(domain_dfa_id);

        invariants_bdd_ = var_mgr_->cudd_mgr()->bddOne();
        for (const auto& inv : invariants_)
            invariants_bdd_ = invariants_bdd_ * invariant_to_bdd(domain_dfa_id, inv);

        // construct output object
        SymbolicStateDfa symbolic_dfa(var_mgr_, domain_dfa_id, dfa_initial_state, transition_function, final_states);

        return symbolic_dfa;
    }

    std::vector<CUDD::BDD> LTLfFONDDomain::get_transition_function(std::size_t automaton_id, const CUDD::BDD& agent_mutex, const CUDD::BDD& env_mutex) const {

        std::vector<CUDD::BDD> transition_function;

        // auxiliar vectors to construct add and delete bdds
        std::vector<CUDD::BDD> add_bdds(vars_.size(), var_mgr_->cudd_mgr()->bddZero());
        std::vector<CUDD::BDD> del_bdds(vars_.size(), var_mgr_->cudd_mgr()->bddZero());

        // assign actions to add and del bdds of vars
        for (const auto& act : actions_) {
            auto act_add_list = act.get_add_list();
            auto act_del_list = act.get_del_list();
            for (const auto& id : act_add_list) {
                add_bdds[id] = add_bdds[id] + act.get_action_bdd();
            }
            for (const auto& id : act_del_list) {
                del_bdds[id] = del_bdds[id] + act.get_action_bdd();
            }
        }

        // construct bdds in transition function
        for (int i = 0; i < vars_.size(); ++i) {
            CUDD::BDD var_bdd =
                ((var_mgr_->state_variable(automaton_id, i) * !(del_bdds[i])) +
                (add_bdds[i]));
            transition_function.push_back(var_bdd);
        }

        // construct a Boolean formula that is SAT if and only if
        // agent (resp. env) respects action (resp. reaction) preconditions
        CUDD::BDD agent_pre_bdd = get_agent_pre(automaton_id);
        CUDD::BDD env_pre_bdd = get_env_pre(automaton_id);

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

    CUDD::BDD LTLfFONDDomain::get_agent_pre(std::size_t domain_dfa_id) const {
        CUDD::BDD agent_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
        std::unordered_set<std::string> added_action_names;
        int i = 0;
        for (const auto& act: actions_) {
            std::string action_reaction_name = act.get_action_name();

            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            if (added_action_names.find(action_name) == added_action_names.end()) { // action name has not been added to agent pre

                added_action_names.insert(action_name);

                auto act_pos_pre = act.get_pos_pre();
                auto act_neg_pre = act.get_neg_pre();
                CUDD::BDD act_pre_bdd = var_mgr_->cudd_mgr()->bddOne();
                for (const auto& i : act_pos_pre) act_pre_bdd = act_pre_bdd * var_mgr_->state_variable(domain_dfa_id, i);
                for (const auto& i : act_neg_pre) act_pre_bdd = act_pre_bdd * (!var_mgr_->state_variable(domain_dfa_id, -i));

                act_pre_bdd = ((!act.get_agent_bdd()) + act_pre_bdd);
                agent_pre_bdd = agent_pre_bdd * act_pre_bdd;
            }
            ++i;
        }
        return agent_pre_bdd;
    }

    CUDD::BDD LTLfFONDDomain::get_env_pre(std::size_t domain_dfa_id) const {
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

    CUDD::BDD LTLfFONDDomain::get_final_states(std::size_t domain_dfa_id) const {
        CUDD::BDD final_states = var_mgr_->cudd_mgr()->bddOne();
        for (const auto& i : pos_goal_list_) final_states = final_states * var_mgr_->state_variable(domain_dfa_id, i);
        for (const auto& i : neg_goal_list_) final_states = final_states * !(var_mgr_->state_variable(domain_dfa_id, -i));
        // return only final states without agent or error vars
        // agent or error vars are included depending on the game to be solved
        // i.e., adversarial vs. cooperative
        return final_states;
    }

    CUDD::BDD LTLfFONDDomain::invariant_to_bdd(std::size_t automaton_id, const Invariant& inv) const {
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
        return inv_bdd;
    }

    std::pair<std::unordered_set<std::string>, std::unordered_set<std::string>> LTLfFONDDomain::get_action_reaction_names() const {
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

    std::size_t LTLfFONDDomain::get_bits(const std::unordered_set<std::string>& set) const {
        std::size_t count = 0;
        std::size_t size = set.size() - 1;
        if (size == 0) return 1;
        while (size) {
            ++count;
            size>>=1;
        }
        return count;
    }

    std::pair<std::unordered_set<int>, std::unordered_set<int>> LTLfFONDDomain::get_invariant_vars(const std::vector<std::string>& inv_vec, const std::unordered_map<std::string, int>& var_to_id) const {
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

    std::pair<CUDD::BDD, CUDD::BDD> LTLfFONDDomain::get_action_reaction_vars(const std::unordered_set<std::string>& action_names, const std::unordered_set<std::string>& reaction_names) {

        // create and partition input and output vars
        std::size_t action_bits = get_bits(action_names);
        std::size_t reaction_bits = get_bits(reaction_names);

        for (int i = 0; i < action_bits; ++i) action_vars_.push_back("a_" + std::to_string(i));
        for (int i = 0; i < reaction_bits; ++i) reaction_vars_.push_back("r_" + std::to_string(i));

        var_mgr_->create_named_variables(action_vars_);
        var_mgr_->create_named_variables(reaction_vars_);

        var_mgr_->create_output_variables(action_vars_);
        var_mgr_->create_input_variables(reaction_vars_);

        // define encoding for action and reaction vars
        std::unordered_map<std::string, CUDD::BDD> action_name_to_bdd;
        std::unordered_map<std::string, CUDD::BDD> reaction_name_to_bdd;

        // mutual exlcusion axioms for agent and environment
        CUDD::BDD agent_mutex = var_mgr_->cudd_mgr()->bddZero();
        CUDD::BDD env_mutex = var_mgr_->cudd_mgr()->bddZero();

        // encode agent actions and env reactions in binary
        // leftmost bit -> least significant; rightmost bit -> most significant
        int act_int_id = 0, react_int_id = 0;
        for (const auto& action_name : action_names) {
            std::vector<int> act_bin_id = to_bits(act_int_id, action_bits);
            CUDD::BDD act_bdd = var_mgr_->cudd_mgr()->bddOne();
            std::string act_props = "";
            for (int i = 0; i < act_bin_id.size(); ++i) {
                if (act_bin_id[i] == 1) {
                    act_bdd = act_bdd * var_mgr_->name_to_variable("a_"+std::to_string(i));
                    act_props = act_props + "a_" + std::to_string(i) + " && ";
                }
                else if (act_bin_id[i] == 0) {
                    act_bdd = act_bdd * !(var_mgr_->name_to_variable("a_"+std::to_string(i)));
                    act_props = act_props + "!a_" + std::to_string(i) + " && ";
                }
            }
            act_props = ("(" + act_props.substr(0, act_props.size() - 4) + ")");
            action_name_to_props_.insert(std::make_pair(action_name, act_props));
            action_name_to_bdd.insert(std::make_pair(action_name, act_bdd));
            // action_name_to_bin.insert(std::make_pair(action_name, act_bin_id));
            agent_mutex = agent_mutex + act_bdd; // add action bdd to mutual exclusion agent axiom
            id_to_action_name_.insert(std::make_pair(act_int_id, action_name));
            ++act_int_id;
        }

        for (const auto& reaction_name : reaction_names) {
            std::vector<int> react_bin_id = to_bits(react_int_id, reaction_bits);
            CUDD::BDD react_bdd = var_mgr_->cudd_mgr()->bddOne();
            std::string react_props = "";
            for (int i = 0; i < react_bin_id.size(); ++i) {
                if (react_bin_id[i] == 1) {
                    react_bdd = react_bdd * var_mgr_->name_to_variable("r_"+std::to_string(i));
                    react_props = react_props + "r_" + std::to_string(i) + " && ";
                }
                else if (react_bin_id[i] == 0) {
                    react_bdd = react_bdd * !(var_mgr_->name_to_variable("r_"+std::to_string(i)));
                    react_props = react_props + "!r_" + std::to_string(i) + " && ";
                }
            }
            react_props = ("(" + react_props.substr(react_props.size() - 4) + ")");
            reaction_name_to_props_.insert(std::make_pair(reaction_name, react_props));
            reaction_name_to_bdd.insert(std::make_pair(reaction_name, react_bdd));
            env_mutex = env_mutex + react_bdd; // add reaction bdd to mutual exclusion env axiom
            id_to_reaction_name_.insert(std::make_pair(react_int_id, reaction_name));
            ++react_int_id;
        }

        // assign encoding to action_reaction_names
        // TODO. this code is a little bit inefficient
        // creates a new set of actions and substitute it
        // with the existing one. Can we avoid it?
        std::unordered_set<Action, ActionHash> updated_actions;
        for (Action act : actions_) {
            std::string action_reaction_name = act.get_action_name();

            // finds where action and reaction name splits
            int split_index = action_reaction_name.find("_REACT");

            std::string reaction_name = action_reaction_name.substr(split_index);
            std::string action_name = boost::replace_all_copy(action_reaction_name, reaction_name, "");

            act.set_agent_bdd(action_name_to_bdd[action_name]);
            act.set_env_bdd(reaction_name_to_bdd[reaction_name]);
            act.set_action_bdd(action_name_to_bdd[action_name] * reaction_name_to_bdd[reaction_name]);

            updated_actions.insert(act);
        }

        actions_ = updated_actions;

        return std::make_pair(CUDD::BDD(agent_mutex), CUDD::BDD(env_mutex));
    }

    void LTLfFONDDomain::print_domain() const {
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

        std::cout << "Action-reaction pairs: " << std::endl;
        for (auto const& act : actions_) {act.print(); std::cout << std::endl;}
        std::cout << "Number of action-reaction pairs: " << actions_.size() << std::endl;
        std::cout << std::endl;

        std::cout << "Agent actions: " << std::endl;
        for (const auto& p : id_to_action_name_)
            std::cout << "ID: " << p.first << ". Name: " << p.second << std::endl;
        std::cout << "Number of agent actions: " << id_to_action_name_.size() << std::endl;
        std::cout << std::endl;

        std::cout << "Environment actions: " << std::endl;
        for (const auto& p : id_to_reaction_name_)
            std::cout << "ID: " << p.first << ". Name: " << p.second << std::endl;
        std::cout << "Number of environment reactions: " << id_to_reaction_name_.size() << std::endl;
        std::cout << std::endl;

        std::cout << "Number of invariants: " << invariants_.size() << std::endl;
        std::cout << std::endl;
        for (auto const& inv : invariants_) {inv.print(); std::cout << std::endl;}

        std::cout << "##########################################" << std::endl;
    }

    std::string LTLfFONDDomain::parse_goal(const Domain& domain, std::string& goal) const {
        std::string parsed_goal = goal;

        // get maps from: action names to props; and var names to bdds
        std::unordered_map<std::string, std::string> action_names_to_props =
            domain.get_action_name_to_props();
        std::unordered_map<std::string, CUDD::BDD> var_name_to_bdd =
            var_mgr_->get_name_to_variable();

        // copy is needed because of mismatch between SPOT's and Lydia's syntax
        std::string copy = goal;
        boost::algorithm::replace_all(copy, "true", "tt");

        // parse formula with spot parser to get props
        formula spot_intent = parse_formula(copy.c_str());
        std::vector<std::string> props = get_props(spot_intent);

        // perform substituion
        for (auto& p : props) {
            if (p == "tt") continue;
            if (var_name_to_bdd.find(p) == var_name_to_bdd.end()) { // p is not a fluent
                auto it = action_names_to_props.find(p);
                if (it != action_names_to_props.end()) {
                    size_t pos = parsed_goal.find(p);
                    while (pos != std::string::npos) {
                        parsed_goal.replace(pos, p.size(), it->second);
                        pos = parsed_goal.find(p, pos + it->second.size());
                    }
                }
                else throw std::runtime_error(p + " is neither a fluent nor an action name");
            }
        }
        std::cout << parsed_goal << std::endl;
        return parsed_goal;
    }

    void LTLfFONDDomain::interactive(
        const Domain& domain,
        const SymbolicStateDfa& product,
        const MaxSet& max_set
    ) const {
        // keep in mind the order of variables
        // i.e., (F, Act, React)
        // var_mgr_->print_varmgr();
        domain.print_domain();
        var_mgr_->print_varmgr();

        std::vector<int> state = product.initial_state();
        std::vector<CUDD::BDD> transition_function = product.transition_function();
        CUDD::BDD final_states = product.final_states();
        int number_of_fluents = domain.get_vars().size() + 2;

        bool is_action_valid = false;

        std::cout << "[pddl2dfa] Planning domain interactive debug" << std::endl;

        std::cout << "[pddl2dfa] Agent actions: " << std::endl;
        for (const auto& id_to_act : domain.get_id_to_action_name())
            std::cout << "ID: " << id_to_act.first << ". Action: " << id_to_act.second << std::endl;
        std::cout << std::endl;

        std::cout << "[pddl2dfa] Environment reactions: " << std::endl;
        for (const auto& id_to_react : domain.get_id_to_reaction_name())
            std::cout << "ID: " << id_to_react.first << ". Reaction: " << id_to_react.second << std::endl;
        std::cout << std::endl;

        // Obtain the indexes for the agent error state and the environment error state
        std::vector<std::string> vars_ = domain.get_vars();
        std::size_t agent_error_index = vars_.size();
        std::size_t env_error_index = vars_.size() + 1;

        // Obtain the agent error bdd and the environment error bdd from the transition function
        CUDD::BDD agent_error_bdd = product.transition_function()[agent_error_index];
        CUDD::BDD env_error_bdd = product.transition_function()[env_error_index];

        // Construct the strategy to not fall into the environment error bdd
        CUDD::BDD max_env_strategy = max_set.deferring_strategy * !env_error_bdd;

        while (true) {
          	std::vector<int> transition;
            std::vector<int> first_part;
            std::vector<int> actions_bit;
            std::vector<int> reactions_bit;
            std::vector<int> second_part;
			std::vector<int> valid_actions;
			std::vector<int> valid_reactions;
			std::vector<int> legal_reactions;
            std::vector<int> state_prime;
            is_action_valid = false;

            std::cout << "[pddl2dfa] State vector: ";
            for (const auto& v : state) std::cout << v;
            std::cout << std::endl;
            std::string string_state = "{";
            for (int i = 0; i < vars_.size(); ++i)
                if (state[i] == 1) string_state += vars_[i] + ", ";
            string_state = string_state.substr(0, string_state.size() - 2) + "}";
            std::cout << "[pddl2dfa] State vars: " << string_state << std::endl;
            std::cout << "[pddl2dfa] Final states: " << final_states << std::endl;

            state_prime.insert(state_prime.end(), state.begin(), state.begin() + number_of_fluents);
            for(int i = 0; i < var_mgr_->output_variable_count(); ++i) {
              state_prime.push_back(1);
            }
            for(int i = 0; i < var_mgr_->input_variable_count(); ++i) {
              state_prime.push_back(1);
            }
            state_prime.insert(state_prime.end(), state.begin() + number_of_fluents, state.end());

            std::cout << "[pddl2dfa] The current state is: ";
            if (var_mgr_->state_variable(product.automaton_id(), vars_.size()).Eval(state_prime.data()).IsOne())
                std::cout << "- AGENT ERROR STATE -";
            if (var_mgr_->state_variable(product.automaton_id(), vars_.size()+1).Eval(state_prime.data()).IsOne())
                std::cout << "- ENVIRONMENT ERROR STATE -";
            if (final_states.Eval(state_prime.data()).IsOne()) std::cout << "- FINAL -";
            else std::cout << "- NOT FINAL -";
            std::cout << std::endl;

            first_part.insert(first_part.end(), state.begin(), state.begin() + number_of_fluents);
            second_part.insert(second_part.end(), state.begin() + number_of_fluents, state.end());
            transition.insert(transition.end(), first_part.begin(), first_part.end());

            auto id_to_action_name = domain.get_id_to_action_name();
            int act_id;

            // Show valid actions until the user chooses a valid one
           	while(!is_action_valid) {
                valid_actions.clear();
                std::cout << "[pddl2dfa] Valid actions:" << std::endl;
              	for(const auto& id_act : id_to_action_name) {
              		std::vector<int> check_action;
              		check_action.insert(check_action.end(), state.begin(), state.begin() + number_of_fluents);
              		for (const auto& b : to_bits(id_act.first, var_mgr_->output_variable_count())) check_action.push_back(b);

              		if(!agent_error_bdd.Eval(check_action.data()).IsOne()) {
                        valid_actions.push_back(id_act.first);
              			std::cout << "ID: " << id_act.first << " - Action: " << id_act.second << std::endl;
              		}
            	}
            	std::cout << "[pddl2dfa] Insert ID of agent action: ";
            	std::cin >> act_id;
            	if(std::count(valid_actions.begin(), valid_actions.end(), act_id) > 0) {
              		is_action_valid = true;
              		for (const auto& b : to_bits(act_id, var_mgr_->output_variable_count())) transition.push_back(b);
            	} else {
                  	std::cout << "[pddl2dfa] Chosen Action is not valid." << std::endl;
            	}
                std::cout << std::endl;
           	}

            std::cout << "[pddl2dfa] Possible cooperative reactions:" << std::endl;

            // Check the validity for each possible reaction related to the chosen action
            for (const auto& id_to_react : domain.get_id_to_reaction_name()) {
              	std::vector<int> eval;

                eval.insert(eval.end(), first_part.begin(), first_part.end());

                actions_bit = to_bits(act_id, var_mgr_->output_variable_count());
                eval.insert(eval.end(), actions_bit.begin(), actions_bit.end());

                reactions_bit = to_bits(id_to_react.first, var_mgr_->input_variable_count());
                eval.insert(eval.end(), reactions_bit.begin(), reactions_bit.end());

                eval.insert(eval.end(), second_part.begin(), second_part.end());

                if(max_env_strategy.Eval(eval.data()).IsOne()) {
                  std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain.get_id_to_reaction_name()[id_to_react.first] << " - VALID" << std::endl;
                  valid_reactions.push_back(id_to_react.first);
                } else {
                  std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain.get_id_to_reaction_name()[id_to_react.first] << " - NOT VALID" << std::endl;
                }
            }

            // Extract one of valid reaction with a PRNG
            if (!valid_reactions.empty()) {
                std::random_device rd;  // Seed for randomness
                std::mt19937 gen(rd()); // Mersenne Twister PRNG
                std::uniform_int_distribution<size_t> dist(0, valid_reactions.size() - 1);

                size_t randomIndex = dist(gen);
                auto& randomElement = valid_reactions[randomIndex];
				std::cout << std::endl;
				std::cout << "[pddl2dfa] Chosen Reaction is: " << randomElement << ": " << domain.get_id_to_reaction_name()[randomElement] << std::endl;
                for (const auto& b : to_bits(randomElement, var_mgr_->input_variable_count())) transition.push_back(b);
            } else {
              	std::cout << std::endl;
              	std::cout << "[pddl2dfa] No cooperative reaction found" << std::endl;
              	std::cout << "[pddl2dfa] Possible legal reactions:" << std::endl;
              	for (const auto& id_to_react : domain.get_id_to_reaction_name()) {
              		std::vector<int> eval;

                	eval.insert(eval.end(), first_part.begin(), first_part.end());

                	actions_bit = to_bits(act_id, var_mgr_->output_variable_count());
                	eval.insert(eval.end(), actions_bit.begin(), actions_bit.end());

                	reactions_bit = to_bits(id_to_react.first, var_mgr_->input_variable_count());
                	eval.insert(eval.end(), reactions_bit.begin(), reactions_bit.end());

                	eval.insert(eval.end(), second_part.begin(), second_part.end());

                	if(!env_error_bdd.Eval(eval.data()).IsOne()) {
                  		std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain.get_id_to_reaction_name()[id_to_react.first] << " - LEGAL" << std::endl;
                  		legal_reactions.push_back(id_to_react.first);
                	} else {
                  		std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain.get_id_to_reaction_name()[id_to_react.first] << " - NOT LEGAL" << std::endl;
                	}
            	}

                std::random_device rd;  // Seed for randomness
                std::mt19937 gen(rd()); // Mersenne Twister PRNG
                std::uniform_int_distribution<size_t> dist(0, legal_reactions.size() - 1);

                size_t randomIndex = dist(gen);
                auto& randomElement = legal_reactions[randomIndex];
				std::cout << std::endl;
				std::cout << "[pddl2dfa] Chosen Reaction is: " << randomElement << ": " << domain.get_id_to_reaction_name()[randomElement] << std::endl;
                for (const auto& b : to_bits(randomElement, var_mgr_->input_variable_count())) transition.push_back(b);
            }

            transition.insert(transition.end(), second_part.begin(), second_part.end());

            std::vector<int> new_state;
            for (int i = 0; i < transition_function.size(); ++i) {
                new_state.push_back(transition_function[i].Eval(transition.data()).IsOne());
            }
            state = new_state;
            std::cout << std::endl;
        }
        return;
    }
}
