#include<sys/stat.h>
#include<cstring>
#include<iostream>
#include<istream>
#include<memory>
#include<CLI/CLI.hpp>
#include"VarMgr.h"
#include"Domain.h"
#include"Stopwatch.h"
using namespace std;

int main(int argc, char** argv) {

    CLI::App app {
        "pddl2dfa: a tool to convert PDDL planning domain specifications into DFAs"
    };

    string domain_file, problem_file, out_file = "";
    bool interactive = false, print_domain = false, save_results = false;
    int alg_id = -1;

    CLI::Option* domain_file_opt =
        app.add_option("-d,--domain-file", domain_file, "Path to PDDL domain file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* problem_file_opt =
        app.add_option("-p,--problem-file", problem_file, "Path to PDDL problem file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* algorithm_opt =
        app.add_option("-a,--alg", alg_id, "Conversion algorithm.\n\t0: PDDL -> LTLf -> DFA\n\t1: PDDL -> DFA") ->
        required();

    // TODO. Check which information to print in out_file
    CLI::Option* out_file_opt =
        app.add_option("-o,--out-file", out_file, "Path to output csv file. Stores:\n1. PDDL domain file\n2. PDDL problem file\n3. Run time (secs)\n4. PDDL parsing (secs)\n5. Size of DFA (with --alg==1 only)\n6. Number of actions (with --alg==1 only)\n7. Nodes in BDDs (with --alg==1 only)");

    CLI::Option* interactive_opt =
        app.add_option("-i,--interactive", interactive, "Executes interactively the domain DFA (with --alg==1 only)");
    CLI::Option* print_opt =
        app.add_option("-t,--print-domain", print_domain, "Prints the domain");

    CLI11_PARSE(app, argc, argv);

    std::shared_ptr<Syft::VarMgr> var_mgr = std::make_shared<Syft::VarMgr>();

    Syft::Stopwatch pddl_parsing;
    pddl_parsing.start();

    std::cout << "[pddl2dfa] Parsing PDDL domain...";
    Syft::Domain domain(var_mgr, domain_file, problem_file);  
    double t_pddl_parsing = pddl_parsing.stop().count() / 1000.0;
    std::cout << "Done [" << t_pddl_parsing << " s]" << std::endl;

    if (print_domain) domain.print_domain();

    Syft::Stopwatch pddl2dfa;
    pddl2dfa.start();
    double t_pddl2dfa = -1;

    if (alg_id == 1) {
        std::cout << "[pddl2dfa] Transforming PDDL to DFA..." << std::flush;;
        Syft::SymbolicStateDfa domain_dfa = domain.to_symbolic();
        t_pddl2dfa = pddl2dfa.stop().count() / 1000.0;
        std::cout << "Done [" << t_pddl2dfa << " s]" << std::endl;
        
        if (interactive) domain.interactive(domain_dfa);
        if (out_file != "") {
            std::ofstream out_stream(out_file, std::ofstream::app);
            out_stream << domain_file << ","  << problem_file << "," << t_pddl_parsing + t_pddl2dfa << "," << t_pddl_parsing << "," << t_pddl2dfa << "," << domain_dfa.transition_function().size() << "," << domain.get_id_to_action_name().size() << ",";
            std::string bdd_sizes = "";
            for (const auto& bdd : domain_dfa.transition_function()) bdd_sizes += std::to_string(bdd.nodeCount()) + "-";
            out_stream << bdd_sizes.substr(0, bdd_sizes.size()-1) << std::endl;
        }
    } else if (alg_id == 0) {
        std::cout << "[pddl2dfa] Transforming PDDL in LTLf and LTLf in DFA..." << std::flush;
        Syft::SymbolicStateDfa domain_dfa = domain.to_ltlf_and_symbolic();
        t_pddl2dfa = pddl2dfa.stop().count()/1000.0;
        std::cout << "Done [" << t_pddl2dfa << " s]" << std::endl;
        if (out_file != "") {
            std::ofstream out_stream(out_file, std::ofstream::app);
            out_stream << domain_file << ","  << problem_file << "," << t_pddl_parsing + t_pddl2dfa << "," << t_pddl_parsing << "," << t_pddl2dfa << std::endl;
        }
    } else {
        std::cerr << "Non-existing algorithm. Termination" << std::endl;
        return 1;
    }
    return 0;
}
