//
// Created by antonio on 3/25/25.
//
#include"LTLfFONDDomainExposed.h"

namespace Syft {
LTLfFONDDomainExposed::LTLfFONDDomainExposed(
    std::shared_ptr<Syft::VarMgr> var_mgr,
    Syft::SymbolicStateDfa *symbolic_DFA,
    const Syft::Domain *domain,
    const Syft::MaxSet *bdd
) : var_mgr_(std::move(var_mgr)), symbolic_DFA_(symbolic_DFA), domain_(domain), max_set_(bdd) {}

std::vector<int> LTLfFONDDomainExposed::to_bits(int i, std::size_t size) const {
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

void LTLfFONDDomainExposed::execute(int action_id) {
    std::vector<int> state = symbolic_DFA_->initial_state();
    std::vector<CUDD::BDD> transition_function = symbolic_DFA_->transition_function();
    int number_of_fluents = domain_->get_vars().size() + 2;
    std::vector<int> transition;
    std::vector<int> first_part;
    std::vector<int> actions_bit;
    std::vector<int> reactions_bit;
    std::vector<int> second_part;
    std::vector<int> valid_reactions;
    std::vector<int> legal_reactions;

    std::vector<std::string> vars_ = domain_->get_vars();
    std::size_t env_error_index = vars_.size() + 1;

    // Obtain the environment error bdd from the transition function
    CUDD::BDD env_error_bdd = symbolic_DFA_->transition_function()[env_error_index];

    // Construct the strategy to not fall into the environment error bdd
    CUDD::BDD max_env_strategy = max_set_->deferring_strategy * !env_error_bdd;

    getStateVars(state);

    first_part.insert(first_part.end(), state.begin(), state.begin() + number_of_fluents);
    second_part.insert(second_part.end(), state.begin() + number_of_fluents, state.end());
    transition.insert(transition.end(), first_part.begin(), first_part.end());

    for (const auto& b : to_bits(action_id, var_mgr_->output_variable_count())) transition.push_back(b);

	for (const auto& id_to_react : domain_->get_id_to_reaction_name()) {
        std::vector<int> eval;

        eval.insert(eval.end(), first_part.begin(), first_part.end());

        actions_bit = to_bits(action_id, var_mgr_->output_variable_count());
        eval.insert(eval.end(), actions_bit.begin(), actions_bit.end());

        reactions_bit = to_bits(id_to_react.first, var_mgr_->input_variable_count());
        eval.insert(eval.end(), reactions_bit.begin(), reactions_bit.end());

        eval.insert(eval.end(), second_part.begin(), second_part.end());

        if(max_env_strategy.Eval(eval.data()).IsOne()) {
          //std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain_->get_id_to_reaction_name()[id_to_react.first] << " - VALID" << std::endl;
          valid_reactions.push_back(id_to_react.first);
        } else {
          //std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain_->get_id_to_reaction_name()[id_to_react.first] << " - NOT VALID" << std::endl;
        }
    }

    // Extract one of valid reaction with a PRNG
    if (!valid_reactions.empty()) {
        std::random_device rd;  // Seed for randomness
        std::mt19937 gen(rd()); // Mersenne Twister PRNG
        std::uniform_int_distribution<size_t> dist(0, valid_reactions.size() - 1);

        size_t randomIndex = dist(gen);
        auto& randomElement = valid_reactions[randomIndex];
		/*std::cout << std::endl;
		std::cout << "[pddl2dfa] Chosen Reaction is: " << randomElement << ": " << domain_->get_id_to_reaction_name()[randomElement] << std::endl;*/
        for (const auto& b : to_bits(randomElement, var_mgr_->input_variable_count())) transition.push_back(b);
    } else {
        /*std::cout << std::endl;
        std::cout << "[pddl2dfa] No cooperative reaction found" << std::endl;
        std::cout << "[pddl2dfa] Possible legal reactions:" << std::endl;*/
        for (const auto& id_to_react : domain_->get_id_to_reaction_name()) {
            std::vector<int> eval;

            eval.insert(eval.end(), first_part.begin(), first_part.end());

            actions_bit = to_bits(action_id, var_mgr_->output_variable_count());
            eval.insert(eval.end(), actions_bit.begin(), actions_bit.end());

            reactions_bit = to_bits(id_to_react.first, var_mgr_->input_variable_count());
            eval.insert(eval.end(), reactions_bit.begin(), reactions_bit.end());

            eval.insert(eval.end(), second_part.begin(), second_part.end());

            if(!env_error_bdd.Eval(eval.data()).IsOne()) {
                //std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain_->get_id_to_reaction_name()[id_to_react.first] << " - LEGAL" << std::endl;
                legal_reactions.push_back(id_to_react.first);
            } else {
                //std::cout << "\t - Reaction: " << id_to_react.first << ": " << domain_->get_id_to_reaction_name()[id_to_react.first] << " - NOT LEGAL" << std::endl;
            }
        }

        std::random_device rd;  // Seed for randomness
        std::mt19937 gen(rd()); // Mersenne Twister PRNG
        std::uniform_int_distribution<size_t> dist(0, legal_reactions.size() - 1);

        size_t randomIndex = dist(gen);
        auto& randomElement = legal_reactions[randomIndex];
		/*std::cout << std::endl;
		std::cout << "[pddl2dfa] Chosen Reaction is: " << randomElement << ": " << domain_->get_id_to_reaction_name()[randomElement] << std::endl;*/
        for (const auto& b : to_bits(randomElement, var_mgr_->input_variable_count())) transition.push_back(b);
    }

    transition.insert(transition.end(), second_part.begin(), second_part.end());

    std::vector<int> new_state;
    for (int i = 0; i < transition_function.size(); ++i) {
        new_state.push_back(transition_function[i].Eval(transition.data()).IsOne());
    }
    symbolic_DFA_->setState(new_state);
    state = symbolic_DFA_->initial_state();
    std::cout << std::endl;

    getStateVars(new_state);

    return;
};

void LTLfFONDDomainExposed::getState() {
  	CUDD::BDD final_states = symbolic_DFA_->final_states();
    int number_of_fluents = domain_->get_vars().size() + 2;
    std::vector<int> state = symbolic_DFA_->initial_state();
    std::vector<int> state_prime;
    std::vector<std::string> vars_ = domain_->get_vars();

    state_prime.insert(state_prime.end(), state.begin(), state.begin() + number_of_fluents);
    for(int i = 0; i < var_mgr_->output_variable_count(); ++i) {
        state_prime.push_back(1);
    }
    for(int i = 0; i < var_mgr_->input_variable_count(); ++i) {
        state_prime.push_back(1);
    }
    state_prime.insert(state_prime.end(), state.begin() + number_of_fluents, state.end());

    std::cout << "[pddl2dfa] The current state is: ";
    if (var_mgr_->state_variable(symbolic_DFA_->automaton_id(), vars_.size()).Eval(state_prime.data()).IsOne())
        std::cout << "- AGENT ERROR STATE -";
    if (var_mgr_->state_variable(symbolic_DFA_->automaton_id(), vars_.size()+1).Eval(state_prime.data()).IsOne())
        std::cout << "- ENVIRONMENT ERROR STATE -";
    if (final_states.Eval(state_prime.data()).IsOne()) std::cout << "- FINAL -";
    else std::cout << "- NOT FINAL -";
    std::cout << std::endl;
};

void LTLfFONDDomainExposed::getStateVars() {
    std::vector<int> state = symbolic_DFA_->initial_state();
    std::vector<std::string> vars_ = domain_->get_vars();

    std::string string_state = "{";
    for (int i = 0; i < vars_.size(); ++i)
        if (state[i] == 1) string_state += vars_[i] + ", ";
    string_state = string_state.substr(0, string_state.size() - 2) + "}";
    std::cout << "[pddl2dfa] State vars: " << string_state << std::endl;
};

void LTLfFONDDomainExposed::getStateVars(std::vector<int> state) {
    std::vector<std::string> vars_ = domain_->get_vars();

    std::string string_state = "{";
    for (int i = 0; i < vars_.size(); ++i)
        if (state[i] == 1) string_state += vars_[i] + ", ";
    string_state = string_state.substr(0, string_state.size() - 2) + "}";
    std::cout << "[pddl2dfa] Current state: " << string_state << std::endl;
}
}
