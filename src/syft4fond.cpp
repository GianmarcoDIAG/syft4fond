#include<sys/stat.h>
#include<cstring>
#include<iostream>
#include<istream>
#include<memory>
#include<CLI/CLI.hpp>
#include"VarMgr.h"
#include"FONDSynthesizer.h"
using namespace std;

double sumVec(const std::vector<double>& v) 
{
    double sum = 0;
    for (const auto& d: v) sum += d;
    return sum;
}

int main(int argc, char** argv) {

    CLI::App app {
        "syft4fond: a tool for reactive synthesis in FOND planning domains"
    };

    string domain_file, problem_file, out_file;
    bool interactive = false;

    CLI::Option* domain_file_opt =
        app.add_option("-d,--domain-file", domain_file, "Path to PDDL domain file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* problem_file_opt =
        app.add_option("-p,--problem-file", problem_file, "Path to PDDL problem file") ->
        required() -> check(CLI::ExistingFile);

    CLI::Option* interactive_opt =
        app.add_option("-i,--interactive", interactive, "Executes the synthesized strategy in interactive mode");

    CLI::Option* out_file_opt =
        app.add_option("-o,--out-file", out_file, "Path to output .csv file. Stores:\n1. PDDL domain file\n2. PDDL problem file\n3. Run time (secs)\n4. PDDL parsing (secs)\n5. PDDL2DFA (secs)\n6. Synthesis (secs)\n7. Realizability (0,1)");

    CLI11_PARSE(app, argc, argv);

    std::shared_ptr<Syft::VarMgr> var_mgr = std::make_shared<Syft::VarMgr>();

    Syft::FONDSynthesizer synthesizer(
        var_mgr,
        domain_file, 
        problem_file,
        interactive); 

    Syft::SynthesisResult result = synthesizer.run();

    auto running_times = synthesizer.get_running_times();

    if (result.realizability) {
        std::cout << "[syft4fond] Realizable. Computed strong plan [" << sumVec(running_times) << " s]" << std::endl;
        if (out_file != "") {
            std::ofstream out_stream(out_file, std::ofstream::app);
            out_stream << domain_file << "," << problem_file << "," 
            << sumVec(running_times) << "," << running_times[0] << ","
            << running_times[1] << "," << running_times[2] << "," << 1 << std::endl; 
        }
    } else {
        std::cout << "[syft4fond] Unrealizable. No strong plan exists [" << sumVec(running_times) << " s]" << std::endl;
        if (out_file != "") {
            std::ofstream out_stream(out_file, std::ofstream::app);
            out_stream << domain_file << "," << problem_file << "," 
            << sumVec(running_times) << "," << running_times[0] << ","
            << running_times[1] << "," << running_times[2] << "," << 0 << std::endl; 
        }
    }

    return 0;
}