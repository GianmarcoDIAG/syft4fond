#include "ReachabilitySynthesizer.h"

#include <cassert>

namespace Syft {

ReachabilitySynthesizer::ReachabilitySynthesizer(SymbolicStateDfa spec,
						 Player starting_player, Player protagonist_player,
						 CUDD::BDD goal_states,
						 CUDD::BDD state_space)
    : DfaGameSynthesizer(spec, starting_player, protagonist_player)
    , goal_states_(goal_states), state_space_(state_space),
    winning_states_(spec_.var_mgr()->cudd_mgr()->bddZero()),
    winning_moves_(spec_.var_mgr()->cudd_mgr()->bddZero())
{}


SynthesisResult ReachabilitySynthesizer::run() {
  SynthesisResult result;
  CUDD::BDD winning_states = state_space_ & goal_states_;
  CUDD::BDD winning_moves = winning_states;

  // std::size_t iteration = 0;
  while (true) {
    // std::cout << "Current fixpoint iteration (adversarial): " << iteration << std::endl;
    // std::cout << "Computing preimage... " << std::flush;
    CUDD::BDD preimage_bdd = preimage(winning_states);
    // std::cout << "Done!" << std::endl;
    // std::cout << "Quantification elimination..." << std::flush;
    CUDD::BDD new_winning_moves = winning_moves | (state_space_ & (!winning_states) & preimage_bdd);
//     CUDD::BDD new_winning_moves = winning_moves |
                              //     (state_space_ & (!winning_states) & preimage(winning_states));
    // std::cout << "Done!" << std::endl;

    CUDD::BDD new_winning_states = project_into_states(new_winning_moves);
//     std::cout <<"Done!" << std::endl;

    if (includes_initial_state(new_winning_states)) {
        result.realizability = true;
        result.winning_states = new_winning_states;
        std::unordered_map<int, CUDD::BDD> strategy = synthesize_strategy(
              new_winning_moves);
        result.transducer = std::make_unique<Transducer>(
              var_mgr_, initial_vector_, strategy, spec_.transition_function(),
              starting_player_, protagonist_player_);
        winning_states_ = new_winning_states;
        winning_moves_ = new_winning_moves;
        return result;

    } else if (new_winning_states == winning_states) {
        result.realizability = false;
        result.winning_states = new_winning_states;
        // result.transducer = nullptr;
        std::unordered_map<int, CUDD::BDD> strategy = synthesize_strategy(
              new_winning_moves);

        result.transducer = std::make_unique<Transducer>(
              var_mgr_, initial_vector_, strategy, spec_.transition_function(),
              starting_player_, protagonist_player_);
        winning_states_ = new_winning_states;
        winning_moves_ = new_winning_moves;
        return result;
    }

    winning_moves = new_winning_moves;
    winning_states = new_winning_states;

    // ++iteration; 
  }

}

 CUDD::BDD ReachabilitySynthesizer::get_winning_states() const {
      return winning_states_;
 }

 CUDD::BDD ReachabilitySynthesizer::get_winning_moves() const {
      return winning_moves_;
 }

}
