#include "InputOutputPartition.h"

#include <fstream>
#include <sstream>
#include <unordered_set>

// #include <boost/algorithm/string/classification.hpp>
// #include <boost/algorithm/string/split.hpp>
// #include <boost/algorithm/string/trim.hpp>

namespace Syft {

std::runtime_error InputOutputPartition::bad_file_format_exception(
    std::size_t line_number) {
  return std::runtime_error("Incorrect format in line " +
                            std::to_string(line_number) +
                            " of the partition file.");
}

std::runtime_error InputOutputPartition::error_open_file_exception(
				std::string filename) {
	return std::runtime_error("Error opening file:" + filename + "!");
}
  
InputOutputPartition::InputOutputPartition()
{}

InputOutputPartition InputOutputPartition::read_from_file(
    const std::string& filename) {
  InputOutputPartition partition;		     
			     
  std::ifstream in(filename);
	if (!in.is_open()) {
		throw error_open_file_exception(filename);
	}

	std::unordered_set<std::string> inputs;
	std::unordered_set<std::string> outputs;

	bool readingInputs = false;
	bool readingOutputs = false;

	std::string line;
	while (getline(in, line)) {
		// Skip comment lines (lines starting with '#')
		if (!line.empty() && line[0] == '#') {
			continue;
		}

		std::stringstream ss(line);
		std::string word;

		while (ss >> word) {
			if (word == ".inputs" || word == ".inputs:") {
				readingInputs = true;
				readingOutputs = false;
			} else if (word == ".outputs" || word == ".outputs:") {
				readingInputs = false;
				readingOutputs = true;
			}
			else if (readingInputs) {
				inputs.insert(word);
			} else if (readingOutputs) {
				outputs.insert(word);
			}
		}
	}

	in.close();

	partition.input_variables.assign(inputs.begin(), inputs.end());
	partition.output_variables.assign(outputs.begin(), outputs.end());

  // std::size_t line_number = 1;
  // std::string line;
  // std::getline(in, line);
  //
  // std::vector<std::string> input_substr;
  // split(input_substr, line, boost::is_any_of(":"));
  //
  // if (input_substr.size() != 2 || input_substr[0] != ".inputs") {
  //   throw bad_file_format_exception(line_number);
  // }
  //
  // boost::trim(input_substr[1]); // remove leading and trailing whitespace
  // boost::split(partition.input_variables, input_substr[1],
	 //       boost::is_any_of(" "));
  //
  // ++line_number;
  // std::getline(in, line);
  //
  // std::vector<std::string> output_substr;
  // boost::split(output_substr, line, boost::is_any_of(":"));
  //
  // if (output_substr.size() != 2 || output_substr[0] != ".outputs") {
  //   throw bad_file_format_exception(line_number);
  // }
  //
  // boost::trim(output_substr[1]); // remove leading and trailing whitespace
  // boost::split(partition.output_variables, output_substr[1],
	 //       boost::is_any_of(" "));

  return partition;
}

}
