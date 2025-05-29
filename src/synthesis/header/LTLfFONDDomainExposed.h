//
// Created by antonio on 3/25/25.
//

#include<string>
#include <random>
#include "VarMgr.h"
#include "SymbolicStateDfa.h"
#include "Domain.h"
#include <mona/bdd.h>
#include <iostream>
#include"CoOperativeReachabilitySynthesizer.h"

#ifndef LTLFFONDDOMAINEXPOSED_H
#define LTLFFONDDOMAINEXPOSED_H

namespace Syft {
class LTLfFONDDomainExposed {
  private:
    std::shared_ptr<Syft::VarMgr> var_mgr_;
    Syft::SymbolicStateDfa* symbolic_DFA_;
    const Syft::Domain* domain_;
    const Syft::MaxSet* max_set_;

    std::vector<int> to_bits(int i, std::size_t size) const;

  public:
    LTLfFONDDomainExposed(std::shared_ptr<Syft::VarMgr> var_mgr_, Syft::SymbolicStateDfa* symbolic_DFA, const Syft::Domain* domain, const Syft::MaxSet* bdd);

    void execute(int action_id);
    void getState();
    void getStateVars();
    void getStateVars(std::vector<int> state);
};
}
#endif //LTLFFONDDOMAINEXPOSED_H
