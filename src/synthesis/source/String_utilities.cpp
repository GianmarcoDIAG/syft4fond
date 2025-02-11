
#include "String_utilities.h"

#include <vector>
#include <sstream>
#include <algorithm>
#include <string>

namespace Syft {

  std::vector<std::string> split(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != std::string::npos) {
      if (end != start) {
        tokens.push_back(str.substr(start, end - start));
      }
      start = end + delimiter.length();
    }
    if (start < str.size()) {
      tokens.push_back(str.substr(start));
    }
    return tokens;
  }

  std::vector<std::string> split_any_of(const std::string& str, const std::string& charset) {
    std::vector<std::string> result;
    std::string temp;

    for (char ch : str) {
      if (charset.find(ch) != std::string::npos) {
        if (!temp.empty()) {
          result.push_back(temp);
          temp.clear();
        }
      } else {
        temp += ch;
      }
    }
    if (!temp.empty()) result.push_back(temp);

    return result;
  }

  std::string trim(const std::string& str) {
    std::string trimmed_str = str;
    trimmed_str.erase(trimmed_str.begin(), std::find_if(trimmed_str.begin(), trimmed_str.end(), [](int ch) {
      return !std::isspace(ch);
    }));
    trimmed_str.erase(std::find_if(trimmed_str.rbegin(), trimmed_str.rend(), [](int ch) {
      return !std::isspace(ch);
    }).base(), trimmed_str.end());
    return trimmed_str;
  }

  void trim_if(std::string& str, const std::string& charset) {
    // Trim from the left
    str.erase(str.begin(), std::find_if(str.begin(), str.end(),
                                        [&](char ch) { return !is_any_of(ch, charset); }));

    // Trim from the right
    str.erase(std::find_if(str.rbegin(), str.rend(),
                           [&](char ch) { return !is_any_of(ch, charset); }).base(),
              str.end());
  }

  std::string to_lower_copy(const std::string& str) {
    std::string data = str;
    std::transform(data.begin(), data.end(), data.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return data;
  }

  std::string to_upper_copy(const std::string& str) {
    std::string data = str;
    std::transform(data.begin(), data.end(), data.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return data;
  }

  void replace_all(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
      str.replace(start_pos, from.length(), to);
      start_pos += to.length();
    }
  }

  std::string replace_all_copy(const std::string& str, const std::string& from, const std::string& to) {
    std::string result = str;
    size_t start_pos = 0;
    while ((start_pos = result.find(from, start_pos)) != std::string::npos) {
      result.replace(start_pos, from.length(), to);
      start_pos += to.length(); // Move past the replaced part
    }
    return result;
  }


}
