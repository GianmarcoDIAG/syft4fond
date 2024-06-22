/*
 * Definition of class FONDSynthesizer 
*/

#include"FONDSynthesizer.h"

namespace Syft {



    FONDSynthesizer::FONDSynthesizer(
        std::shared_ptr<Syft::VarMgr> var_mgr,
        const std::string& domain_file,
        const std::string& problem_file,
        bool interactive
    ) : var_mgr_(var_mgr),
        domain_file_(domain_file),
        problem_file_(problem_file), 
        interactive_(interactive) {}

    SynthesisResult FONDSynthesizer::run() {
        SynthesisResult result;

        // parse domain_file and problem_file to construct domain
        Syft::Stopwatch pddl_parsing;
        pddl_parsing.start();

        std::cout << "[pddl2dfa] Parsing PDDL domain...";
        Domain domain(var_mgr_, domain_file_, problem_file_);
        double t_pddl_parsing = pddl_parsing.stop().count() / 1000.0;
        std::cout << "Done [" << t_pddl_parsing << " s]" << std::endl;

        running_times_.push_back(t_pddl_parsing);

        // transform domain into a symbolic DFA
        Syft::Stopwatch pddl2dfa;
        pddl2dfa.start();
    
        std::cout << "[pddl2dfa] Transforming PDDL to DFA..." << std::flush;;
        SymbolicStateDfa domain_dfa = domain.to_symbolic();
        double t_pddl2dfa = pddl2dfa.stop().count() / 1000.0;
        std::cout << "Done [" << t_pddl2dfa << " s]" << std::endl;

        running_times_.push_back(t_pddl2dfa);

        // domain.print_domain();
        Syft::Stopwatch synthesis;
        synthesis.start();

        std::cout << "[syft4fond] Synthesizing strategy..." << std::flush;
        std::size_t agent_error_index = domain.get_vars().size();
        std::size_t env_error_index = domain.get_vars().size() + 1;

        CUDD::BDD agent_error_var = var_mgr_->get_state_variables(domain_dfa.automaton_id()).at(agent_error_index);
        CUDD::BDD env_error_var = var_mgr_->get_state_variables(domain_dfa.automaton_id()).at(env_error_index);

        CUDD::BDD adv_final_states = (!agent_error_var) * (env_error_var + domain_dfa.final_states());
        // construct cooperative goal after solving adversarial game
        // search for cooperative strategy to reach winning region
        // CUDD::BDD coop_final_states = (!agent_error_var) * (!env_error_var) * (domain_dfa.final_states());

        // gets invariant of domain problem
        CUDD::BDD invariant_bdd = domain.get_invariants_bdd();

        // synthesize strategy
        ReachabilitySynthesizer adv_synthesizer(
            domain_dfa,
            Player::Agent,
            Player::Agent,
            adv_final_states * invariant_bdd,
            invariant_bdd
        );
        result = adv_synthesizer.run();
        double t_synthesis = synthesis.stop().count() / 1000.0;
        std::cout << "Done [" << t_synthesis << " s]" << std::endl;

        running_times_.push_back(t_synthesis);

        if (result.realizability && interactive_) interactive(domain, domain_dfa, result);        
        return result;
    }

    void FONDSynthesizer::interactive(const Domain& domain, const SymbolicStateDfa& domain_dfa, const SynthesisResult& result) const {
        std::cout << "[syft4fond] Strategy interactive debugging" << std::endl;

        // var_mgr_->print_varmgr();
        domain.print_domain();

        // auxiliary data structures
        std::map<int, std::string> id_to_action_name = domain.get_id_to_action_name();
        std::map<int, std::string> id_to_reaction_name = domain.get_id_to_reaction_name();
        std::vector<std::string> domain_vars = domain.get_vars();
        std::vector<CUDD::BDD> transition_function = domain_dfa.transition_function();
        CUDD::BDD final_states = domain_dfa.final_states();
        CUDD::BDD agent_error_var = var_mgr_->state_variable(domain_dfa.automaton_id(), domain_vars.size());
        CUDD::BDD env_error_var = var_mgr_->state_variable(domain_dfa.automaton_id(), domain_vars.size()+1);
        std::unordered_map<int, std::string> id_to_var = var_mgr_->get_index_to_name();
        std::unordered_map<int, CUDD::BDD> output_function = result.transducer.get() -> get_output_function();


        std::cout << "[syft4fond] Agent actions: " << std::endl;
        for (const auto& id_to_act : id_to_action_name)
            std::cout << "ID: " << id_to_act.first << ". Action: " << id_to_act.second << std::endl;
        std::cout << std::endl;

        std::cout << "[syft4fond] Environment reactions: " << std::endl;
        for (const auto& id_to_react : id_to_reaction_name) 
            std::cout << "ID: " << id_to_react.first << ". Reaction: " << id_to_react.second << std::endl;
        std::cout << std::endl;

        // order of variables (F, Act, React)
        // construct initial state
        std::vector<int> state = domain_dfa.initial_state();

        while (true) {
            std::cout << "[syft4fond] State vector: ";
            for (const auto& v : state) std::cout << v;
            std::cout << std::endl;

            std::string string_state = "{";
            for (int i = 0; i < domain_vars.size(); ++i) 
                if (state[i] == 1) string_state += domain_vars[i] + ", ";
            string_state = string_state.substr(0, string_state.size() - 2) + "}";
            std::cout << "[syft4fond] State vars: " << string_state << std::endl;

            // TODO. Is it possible for the agent forcing the game into the environment error state?
            std::cout << "[syft4fond] The current state is: " << std::flush;
            if (agent_error_var.Eval(state.data()).IsOne())
                {std::cout << "AGENT ERROR STATE. The agent violated an action precondition. Termination" << std::endl; return;}
            if (env_error_var.Eval(state.data()).IsOne()) 
                {std::cout << "ENVIRONMENT ERROR STATE. The environment violated a reaction precondition. Terminiation" << std::endl; return;}
            if (final_states.Eval(state.data()).IsOne())
                {std::cout << "FINAL. The agent reached the goal. Termination" << std::endl; return;}
            else {std::cout << "NOT FINAL" << std::endl;}
            // std::cout << std::endl;

            std::vector<int> transition = state;
            
            // get agent action
            std::vector<int> bin_agent_action;
            std::size_t domain_dfa_vars = domain_vars.size() + 2;
            for (int i = domain_dfa_vars; i < domain_dfa_vars + id_to_var.size(); ++i) {
                // agent vars bin encoding
                std::string var = id_to_var[i];
                int agent_eval;
                if (var_mgr_->is_output_variable(var)) {
                    std::cout << "[syft4fond] Var ID: " << i << std::flush;
                    std::cout << ". Var name: " << var << std::flush;
                    agent_eval = output_function[i].Eval(state.data()).IsOne();
                    transition.push_back(agent_eval);
                    bin_agent_action.push_back(agent_eval);
                    std::cout << ". Agent eval: " << agent_eval << std::endl;
                }
            }
            std::cout << "[syft4fond] ID of agent action: " << to_int(bin_agent_action) << std::endl;
            std::cout << "[syft4fond] Agent action: " << id_to_action_name[to_int(bin_agent_action)] << std::endl;

            std::cout << "[syft4fond] Insert ID of environment reaction: " << std::flush;
            int react_id;
            std::cin >> react_id;
            // std::cout << std::endl;
            for (const auto& b : to_bits(react_id, var_mgr_->input_variable_count())) transition.push_back(b);

            std::cout << "[syft4fond] Input to transition function: " << std::flush;
            for (const auto& v : transition) std::cout << v;
            std::cout << std::endl;

            std::vector<int> new_state;
            for (int i = 0; i < transition_function.size(); ++i) 
                new_state.push_back(transition_function[i].Eval(transition.data()).IsOne());

            state = new_state;
            std::cout << std::endl;
        }
    }

    std::vector<int> FONDSynthesizer::to_bits(int i, std::size_t size) const {
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

    int FONDSynthesizer::to_int(const std::vector<int>& bits) const {
        int value;
        if (bits[0] == 0) value = 0;
        else value = 1;
        for (int i = 1; i < bits.size(); ++i) 
            value += pow(2*bits[i], i); 
        return value;
    }
}