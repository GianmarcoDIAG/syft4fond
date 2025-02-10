
#ifndef LYDIASYFT_STRING_UTILITIES_H
#define LYDIASYFT_STRING_UTILITIES_H

#include <string>
#include <vector>


namespace Syft {

  std::vector<std::string> split(const std::string& str, const std::string& delimiter = " ");
  std::vector<std::string> split_any_of(const std::string& str, const std::string& charset);
  std::string trim(const std::string& str);
  void trim_if(std::string& str, const std::string& charset);
  std::string to_lower_copy(const std::string& str);
  std::string to_upper_copy(const std::string& str);
  void replace_all(std::string& str, const std::string& from, const std::string& to);
  std::string replace_all_copy(const std::string& str, const std::string& from, const std::string& to);
  inline bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
  }
  inline bool is_any_of(char ch, const std::string& charset) {
    return charset.find(ch) != std::string::npos;
  }
}

#endif //LYDIASYFT_STRING_UTILITIES_H
