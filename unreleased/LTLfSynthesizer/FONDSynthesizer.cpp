/*
 * Definition of class FONDSynthesizer 
*/

#include"FONDSynthesizer.h"

namespace Syft {

    FONDSynthesizer::FONDSynthesizer(
        std::shared_ptr<Syft::VarMgr> var_mgr,
        const std::string& domain_file,
        const std::string& problem_file,
        const std::string& ltlf_goal
    ) : var_mgr_(var_mgr),
        domain_file_(domain_file),
        problem_file_(problem_file),
        ltlf_goal_(ltlf_goal) {}

    BestEffortSynthesisResult FONDSynthesizer::run() {
        // TODO. Add instructions to store running times
        // parse domain_file and problem_file to construct domain
        std::cout << "Parsing PDDL domain...";
        Domain domain(var_mgr_, domain_file_, problem_file_);
        std::cout << "Done!" << std::endl;

        // transform domain into a symbolic DFA
        std::cout << "Transforming PDDL to symbolic DFA..." << std::flush;;
        SymbolicStateDfa domain_dfa = domain.to_symbolic();
        std::cout << "Done!" << std::endl;

        // domain.print_domain();

        // transform LTLf agent goal G into a symbolic DFA A_G
        std::cout << "Transforming LTLf goal to symbolic DFA..." << std::flush;;
        ExplicitStateDfaMona ltlf_mona_dfa = ExplicitStateDfaMona::dfa_of_formula(ltlf_goal_);

        // debug
        // ltlf_mona_dfa.dfa_print();

        std::vector<std::string> ltlf_vars = ltlf_mona_dfa.names;
        std::sort(ltlf_vars.begin(), ltlf_vars.end());

        // debug
        // std::cout << "Fluent vars in LTLf goal: ";
        // for (const auto& v : ltlf_vars) std::cout << v << " ";
        // std::cout << std::endl;

        var_mgr_->create_named_variables(ltlf_vars);

        ExplicitStateDfa ltlf_dfa = ExplicitStateDfa::from_dfa_mona(var_mgr_, ltlf_mona_dfa);
        SymbolicStateDfa ltlf_goal_dfa = SymbolicStateDfa::from_explicit(ltlf_dfa);
        std::cout << "Done!" << std::endl;
        // var_mgr_->assign_state_variables(ltlf_goal_dfa.automaton_id(), ltlf_vars);
        // ltlf_goal_dfa.dump_dot("ltlf_goal_dfa.dot");
        // var_mgr_->print_varmgr();

        // compose planning domain and goal dfas 
        std::vector<std::string> domain_vars = domain.get_vars();

        std::cout << "Constructing game arena..." << std::flush;;
        SymbolicStateDfa game_arena = compose(domain_vars, domain.get_action_vars(), domain.get_reaction_vars(), ltlf_vars, domain_dfa, ltlf_goal_dfa);
        std::cout << "Done!" << std::endl;

        CUDD::BDD agent_error_var = var_mgr_->get_state_variables(domain_dfa.automaton_id()).at(domain_vars.size());
        CUDD::BDD env_error_var = var_mgr_->get_state_variables(domain_dfa.automaton_id()).at(domain_vars.size() + 1);
        CUDD::BDD adv_final_states = !agent_error_var * (env_error_var + ltlf_goal_dfa.final_states());
        CUDD::BDD coop_final_states = !agent_error_var * !env_error_var * ltlf_goal_dfa.final_states();

        // synthesize strategy
        std::cout << "Synthesizing strategy..." << std::flush;;
        ReachabilitySynthesizer adv_synthesizer(
            game_arena,
            Player::Agent,
            Player::Agent,
            adv_final_states,
            var_mgr_->cudd_mgr()->bddOne()
        );
        CoOperativeReachabilitySynthesizer coop_synthesizer(
            game_arena,
            Player::Agent,
            Player::Agent,
            coop_final_states,
            var_mgr_->cudd_mgr()->bddOne()
        );
        BestEffortSynthesisResult result;
        result.adversarial = adv_synthesizer.run();
        result.cooperative = coop_synthesizer.run();
        std::cout << "Done!" << std::endl;
        interactive(domain, domain_dfa, game_arena, result);
        return result;
    }

    SymbolicStateDfa FONDSynthesizer::compose(
        const std::vector<std::string>& domain_vars,
        const std::vector<std::string>& act_vars,
        const std::vector<std::string>& react_vars,
        const std::vector<std::string>& ltlf_vars,
        const SymbolicStateDfa& domain_dfa,
        const SymbolicStateDfa& ltlf_goal_dfa) const {
            // remember the order in which variables are created
            // (F, Act, React, F_{LTLf}, Z)

            // construct map F_{LTLf} -> id
            // id is position of F_{LTLf} in domain_vars
            // auxiliary data structure
            std::map<std::string, std::size_t> var_to_id;
            for (const auto& var : ltlf_vars) {
                auto it = std::find(domain_vars.begin(), domain_vars.end(), var);
                if (it != domain_vars.end()) { // var is in domain
                    std::size_t i = it - domain_vars.begin();
                    var_to_id.insert(std::make_pair(var, i));
                    }
                else {
                    throw std::runtime_error("LTLf var: " + var + " does not appear in domain");
                    exit(1);
                }
            }

            // debug
            // std::cout << "LTLf_var: Domain_index" << std::endl;
            // for (const auto& v_i : var_to_id) {
                // std::cout << v_i.first + ": " + std::to_string(v_i.second) << std::endl;
            // }
            // std::cout << std::endl; 

            // (1) product_id
            std::vector<std::size_t> input_dfa_ids = {domain_dfa.automaton_id(), ltlf_goal_dfa.automaton_id()};
            std::size_t product_id = var_mgr_->create_product_state_space(input_dfa_ids);

            // (2) initial_state
            // (i) evaluate goal DFA in domain initial state
            std::vector<int> eval_vector;
            std::vector<int> domain_dfa_init = domain_dfa.initial_state();
            std::vector<int> goal_dfa_init = ltlf_goal_dfa.initial_state();
            eval_vector.insert(eval_vector.end(), domain_dfa_init.begin(), domain_dfa_init.end()); // F
            for (int i = 0; i < var_mgr_->output_variable_count(); ++i) eval_vector.push_back(0); // Act
            for (int i = 0; i < var_mgr_->input_variable_count(); ++i) eval_vector.push_back(0); // React
            for (const auto& var : ltlf_vars) eval_vector.push_back(domain_dfa_init[var_to_id[var]]); // F_{LTLf}
            eval_vector.insert(eval_vector.end(), goal_dfa_init.begin(), goal_dfa_init.end());
            // for (int i = 0; i < var_mgr_->state_variable_count(ltlf_goal_dfa.automaton_id()); ++i) eval_vector.push_back(0); // Z

            // debug
            // std::cout << "Evaluation vector (F, Act, React, F^ , Z): " << std::endl;
            // for (const auto& v : eval_vector) std::cout << v;
            // std::cout << std::endl;

            std::vector<int> goal_dfa_synch_init;
            for (const auto& bdd : ltlf_goal_dfa.transition_function()) goal_dfa_synch_init.push_back(bdd.Eval(eval_vector.data()).IsOne());

            // debug
            // std::cout << "Initial state in goal symbolic DFA: " << std::endl;
            // for (const auto& v : goal_dfa_init) std::cout << v;
            // std::cout << std::endl; 

            // (ii) construct initial_state vector
            // state vars in arena are (F, Z)
            std::vector<int> initial_state;
            initial_state.insert(initial_state.end(), domain_dfa_init.begin(), domain_dfa_init.end()); // F
            // for (const auto& var : ltlf_vars) eval_vector.push_back(domain_dfa_init[var_to_id[var]]); // F_{LTLf}
            initial_state.insert(initial_state.end(), goal_dfa_init.begin(), goal_dfa_init.end()); // Z

            // (3) transition_function
            // creates substitution vector
            std::vector<CUDD::BDD> substitution_vector;

            // F <-> F
            for (const auto& var : var_mgr_->get_state_variables(domain_dfa.automaton_id())) 
                substitution_vector.push_back(var);

            // Act <-> Act
            for (const auto& var : act_vars)
                substitution_vector.push_back(var_mgr_->name_to_variable(var));

            // React <-> React
            for (const auto& var : react_vars)
                substitution_vector.push_back(var_mgr_->name_to_variable(var));

            // F_{LTLf} <-> \eta(F, Act, React)
            for (const auto& var : ltlf_vars)
                substitution_vector.push_back(domain_dfa.transition_function().at(var_to_id[var]));

            // Z <-> Z
            for (const auto& var : var_mgr_->get_state_variables(ltlf_goal_dfa.automaton_id()))
                substitution_vector.push_back(var);

            // debug
            // std::cout << "Size of substitution vector: " << substitution_vector.size() << std::endl;
            // std::cout << "Substitution vector: " << std::endl;
            // for (const auto& sub : substitution_vector) 
                // std::cout << sub << std::endl;
            // std::cout << std::endl;

            std::vector<CUDD::BDD> domain_dfa_transition_function = domain_dfa.transition_function();
            std::vector<CUDD::BDD> goal_dfa_transition_function = ltlf_goal_dfa.transition_function();
            std::vector<CUDD::BDD> synch_transition_function;
            synch_transition_function.insert(synch_transition_function.end(), domain_dfa_transition_function.begin(), domain_dfa_transition_function.end());
            for (const auto& bdd : goal_dfa_transition_function) synch_transition_function.push_back(bdd.VectorCompose(substitution_vector));

            // debug
            // std::cout << "Size of game initial state vec: " << initial_state.size() << std::endl;
            // std::cout << "Size of game trans func: " << synch_transition_function.size() << std::endl; 
            
            // (4) final states
            // we later define final states when synthesizing the strategy
            CUDD::BDD dummy_final_states = var_mgr_->cudd_mgr()->bddOne();

            SymbolicStateDfa game_arena = SymbolicStateDfa(var_mgr_, product_id, initial_state, synch_transition_function, dummy_final_states);
            // game_arena.dump_dot("game_arena.dot");
            return game_arena;
    }

    void FONDSynthesizer::interactive(const Domain& domain, const SymbolicStateDfa& domain_dfa, const SymbolicStateDfa& game_arena, const BestEffortSynthesisResult& result) const {
        std::cout << "Strategy interactive debugging" << std::endl;

        domain.print_domain();

        var_mgr_->print_varmgr();

        std::cout << "Agent actions: " << std::endl;
        for (const auto& id_to_act : domain.get_id_to_action_name())
            std::cout << "ID: " << id_to_act.first << ". Action: " << id_to_act.second << std::endl;
        std::cout << std::endl;

        std::cout << "Environment reactions: " << std::endl;
        for (const auto& id_to_react : domain.get_id_to_reaction_name()) 
            std::cout << "ID: " << id_to_react.first << ". Reaction: " << id_to_react.second << std::endl;
        std::cout << std::endl;

        // order of variables (F, Act, React, F_{LTLf}, Z)
        // initial state
        std::vector<int> init_state;
        

    }
}