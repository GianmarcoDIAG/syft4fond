//
// Created by Shufang Zhu on 10/02/2025.
//

#include "ExplicitStateDfaCudd.h"

#include "lydia/utils/cudd.hpp"

namespace Syft {
  ExplicitStateDfaCudd::ExplicitStateDfaCudd(std::shared_ptr<VarMgr> var_mgr)
    : var_mgr_(std::move(var_mgr))
  {}

  ExplicitStateDfaCudd ExplicitStateDfaCudd::from_explicit_dfa(std::shared_ptr<VarMgr> var_mgr,
                                                 const ExplicitStateDfa &explicit_dfa) {

    std::size_t initial_state = explicit_dfa.initial_state();
    std::vector<std::size_t> final_states = explicit_dfa.final_states();
    std::unordered_map<std::size_t, std::vector<std::pair<CUDD::BDD, std::size_t>>> transition_function;

    std::size_t state_count = explicit_dfa.state_count();
    std::vector<CUDD::ADD> transition_function_add = explicit_dfa.transition_function();

    for (std::size_t i = 0; i < state_count; ++i) {
      std::vector<std::pair<CUDD::BDD, std::size_t>> outgoings;
      for (std::size_t j = 0; j < state_count; ++j) {
        CUDD::BDD transition = transition_function_add[i].BddInterval(j, j);
        if (transition != var_mgr->cudd_mgr()->bddZero()) {
          std::pair<CUDD::BDD, std::size_t> edge = std::make_pair(transition, j);
          outgoings.push_back(edge);
        }
      }
      transition_function[i] = outgoings;
    }

    assert(state_count == transition_function.size());

    ExplicitStateDfaCudd dfa(std::move(var_mgr));
    dfa.initial_state_ = initial_state;
    dfa.state_count_ = state_count;
    dfa.final_states_ = std::move(final_states);
    dfa.transition_function_ = std::move(transition_function);
    dfa.variable_names_ = std::move(explicit_dfa.variable_names());

    return dfa;

  }

  std::shared_ptr<VarMgr> ExplicitStateDfaCudd::var_mgr() const {
    return var_mgr_;
  }

  std::size_t ExplicitStateDfaCudd::initial_state() const {
    return initial_state_;
  }

  std::size_t ExplicitStateDfaCudd::state_count() const {
    return state_count_;
  }

  std::vector<std::size_t> ExplicitStateDfaCudd::final_states() const {
    return final_states_;
  }

  std::vector<std::string> ExplicitStateDfaCudd::variable_names() const {
    return variable_names_;
  }


  std::unordered_map<std::size_t, std::vector<std::pair<CUDD::BDD, std::size_t>>> ExplicitStateDfaCudd::transition_function() const {
    return transition_function_;
  }

  std::size_t ExplicitStateDfaCudd::bdd_nodes_count() const {
    std::vector<CUDD::BDD> allBDDs;
    for (const auto& entry : transition_function_) {
      for (const auto& transition : entry.second) {
        allBDDs.push_back(transition.first);
      }
    }
    return var_mgr()->cudd_mgr()->nodeCount(allBDDs);
  }

  // void printPaths(std::shared_ptr<VarMgr> var_mgr, const CUDD::BDD& node, std::vector<char>& path, int level, std::vector<unsigned int> var_order) {
  //   std::cout << "process " << node << "\n";
  //   var_mgr->dump_dot(node.Add(), "node.dot");
  //   if (node.IsZero() || node.IsOne()) {
  //     while (level < var_order.size()) {
  //       path[var_order[level]] = 'X';
  //       level++;
  //     }
  //     if (node.IsOne()) {
  //       for (char val : path) {
  //         std::cout << val;
  //       }
  //     }
  //     return;
  //   }
  //
  //   int var_index = node.NodeReadIndex();  // Get variable index
  //   auto it = std::find(var_order.begin(), var_order.end(), var_index);
  //   assert (it != var_order.end());
  //   int prop_index = std::distance(var_order.begin(), it); // Get the index
  //
  //   // Copy current path and extend it with the new variable
  //   std::vector<char> path_low = path, path_high = path;
  //   path_high[prop_index] = '1'; // High branch (true)
  //   path_low[prop_index] = '0';  // Low branch (false)
  //
  //   std::string var_name = var_mgr->index_to_name(var_index);
  //   CUDD::BDD high_branch, low_branch;
  //   if (Cudd_IsComplement(node.getNode())) {
  //     high_branch = !CUDD::BDD(*var_mgr->cudd_mgr(),Cudd_Regular(Cudd_T(node.getNode())));
  //     low_branch = !CUDD::BDD(*var_mgr->cudd_mgr(),Cudd_Regular(Cudd_E(node.getNode())));
  //   } else {
  //     high_branch = CUDD::BDD(*var_mgr->cudd_mgr(),Cudd_T(node.getNode()));
  //     low_branch = CUDD::BDD(*var_mgr->cudd_mgr(),Cudd_E(node.getNode()));
  //   }
  //
  //   // DdNode *high_node = Cudd_T(node.getNode());
  //   // DdNode *low_node = Cudd_E(node.getNode());
  //   //
  //   //
  //   // CUDD::BDD high_branch(*var_mgr->cudd_mgr(),high_node);
  //   // CUDD::BDD low_branch(*var_mgr->cudd_mgr(),low_node);
  //
  //   std::cout << high_branch << std::endl;
  //   var_mgr->dump_dot(high_branch.Add(), "high.dot");
  //   std::cout << low_branch << std::endl;
  //   var_mgr->dump_dot(low_branch.Add(), "low.dot");
  //
  //   printPaths(var_mgr, high_branch, path_high, level + 1, var_order);
  //   printPaths(var_mgr, low_branch, path_low, level + 1, var_order);
  // }

  void ExplicitStateDfaCudd::dfa_print() const {
    std::cout << "Number of states " +
                         std::to_string(initial_state())
                  << "\n";

    std::cout << "Computed automaton: ";

    std::cout << "DFA with free variables: ";

    for (int i = 0; i < variable_names().size(); i++) {
      std::cout << variable_names()[i] << " " << var_mgr()->name_to_variable(variable_names()[i]);
    }

    std::cout << "\nInitial state: " << initial_state()
      << "\n"
         "Accepting states: ";

    for (int i = 0; i < final_states().size(); i++) {
      std::cout << final_states()[i] << " ";
    }

    std::cout << "\n";


    std::cout << "\nAutomaton has " << state_count() << " state(s) and " << bdd_nodes_count()
      << " BDD-node(s)\n";

    std::cout << "Transitions:\n";

    for (int i = 0; i < state_count(); i++) {
      std::vector<std::pair<CUDD::BDD, std::size_t>> transitions = transition_function()[i];
      for (auto transition : transitions) {

        CUDD::BDD condition = transition.first;
        int var_num = Cudd_ReadSize(condition.manager());
        assert(var_num == var_mgr()->get_index_to_name().size());
        std::vector<std::vector<uint8_t>> cubes= whitemech::lydia::get_cubes(condition, var_num);
        for(auto cube : cubes) {
          std::cout << "State: " << i << ": ";
          for (auto var_name: variable_names()) {
            int var_index = var_mgr()->name_to_variable(var_name).NodeReadIndex();
            int var_value = static_cast<int>(cube[var_index]);
            if (var_value == 2) {
              std::cout << "X";
            } else {
              std::cout << var_value;
            }
          }
          std::cout << " -> state " << transition.second << "\n";
        }

      }
    }
  }

}
