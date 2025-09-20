#include<sys/stat.h>
#include<cstring>
#include<iostream>
#include<istream>
#include<memory>
#include<CLI/CLI.hpp>
#include"VarMgr.h"
#include"Domain.h"
#include"Stopwatch.h"
#include"spotparser.h"
using namespace std;

std::string parse_ltlf_goal(const Syft::Domain& domain, std::string& goal) {
    std::string parsed_goal = goal;

        // get maps from: action names to props; and var names to bdds
        std::unordered_map<std::string, std::string> action_names_to_props =
            domain.get_action_name_to_props();
        std::unordered_map<std::string, CUDD::BDD> var_name_to_bdd =
            domain.get_mgr()-> get_name_to_variable();
        
        // copy is needed because of mismatch between SPOT's and Lydia's syntax
        std::string copy = goal;
        // replace_all(copy, "true", "tt");
    
        // parse formula with spot parser to get props
        // formula spot_intent = parse_formula(intent.c_str());
        formula spot_intent = parse_formula(copy.c_str());
        std::vector<std::string> props = get_props(spot_intent);

        // perform substituion
        for (auto& p : props) {
            if (p == "true") continue;
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
    return parsed_goal;
}

int main(int argc, char** argv) {

    CLI::App app {
        "pddl2ltlf: a tool to convert PDDL planning domain specifications into LTLf"
    };

    string domain_file, problem_file, goal_file, out_ltlf, out_part;

    CLI::Option* domain_file_opt =
        app.add_option("-d,--domain-file", domain_file, "Path to PDDL domain file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* problem_file_opt =
        app.add_option("-p,--problem-file", problem_file, "Path to PDDL problem file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* goal_file_opt =
        app.add_option("-g,--goal-file", goal_file, "Path to LTLf goal file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* out_file_opt =
        app.add_option("-l,--ltlf-file", out_ltlf, "Path to output LTLf formula file");

    CLI::Option* part_file_opt =
        app.add_option("-t,--part-file", out_part, "Path to output partition file");

    CLI11_PARSE(app, argc, argv);

    std::shared_ptr<Syft::VarMgr> var_mgr = std::make_shared<Syft::VarMgr>();

    std::cout << "[pddl2ltlf] Constructing domain object from PDDL specification..." << std::flush;
    Syft::Domain domain(var_mgr, domain_file, problem_file);  
    std::cout << "DONE" << std::endl;

    std::cout << "[pddl2ltlf] Transforming domain and LTLf goal into a single LTLf formula..." << std::flush;

    std::ifstream ltlf_stream(goal_file);
    std::string ltlf_goal;
    std::getline(ltlf_stream, ltlf_goal);

    // ii. parse LTLf goal
    std::string domain_ltlf = domain.domain_to_ltlf();
    ltlf_goal = parse_ltlf_goal(domain, ltlf_goal);
    std::string ltlf_formula = "((" + domain_ltlf + ") -> (G(!ag_err) && F(env_err || (" + ltlf_goal + ")))))";

    std::ofstream out_file_stream(out_ltlf);
    out_file_stream << ltlf_formula << std::flush;
    out_file_stream.close();

    std::ofstream part_file_stream(out_part);
    part_file_stream << domain.get_mgr()->get_part() << std::flush;
    part_file_stream.close();

    std::cout << "[pddl2ltlf] The LTLf formula is: " << ltlf_formula << std::endl;

    return 0;
}