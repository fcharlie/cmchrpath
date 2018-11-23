/////
#include "cmELF.h"
#include "path.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <string>

namespace cmake {
bool RemoveRPath(std::string const &file, std::string *emsg, bool *removed) {
  if (removed) {
    *removed = false;
  }
  int zeroCount = 0;
  unsigned long zeroPosition[2] = {0, 0};
  unsigned long zeroSize[2] = {0, 0};
  unsigned long bytesBegin = 0;
  std::vector<char> bytes;
  {
    // Parse the ELF binary.
    cmELF elf(file.c_str());

    // Get the RPATH and RUNPATH entries from it and sort them by index
    // in the dynamic section header.
    int se_count = 0;
    cmELF::StringEntry const *se[2] = {nullptr, nullptr};
    if (cmELF::StringEntry const *se_rpath = elf.GetRPath()) {
      se[se_count++] = se_rpath;
    }
    if (cmELF::StringEntry const *se_runpath = elf.GetRunPath()) {
      se[se_count++] = se_runpath;
    }
    if (se_count == 0) {
      // There is no RPATH or RUNPATH anyway.
      return true;
    }
    if (se_count == 2 && se[1]->IndexInSection < se[0]->IndexInSection) {
      std::swap(se[0], se[1]);
    }

    // Obtain a copy of the dynamic entries
    cmELF::DynamicEntryList dentries = elf.GetDynamicEntries();
    if (dentries.empty()) {
      // This should happen only for invalid ELF files where a DT_NULL
      // appears before the end of the table.
      if (emsg) {
        *emsg = "DYNAMIC section contains a DT_NULL before the end.";
      }
      return false;
    }

    // Save information about the string entries to be zeroed.
    zeroCount = se_count;
    for (int i = 0; i < se_count; ++i) {
      zeroPosition[i] = se[i]->Position;
      zeroSize[i] = se[i]->Size;
    }

    // Get size of one DYNAMIC entry
    unsigned long const sizeof_dentry =
        elf.GetDynamicEntryPosition(1) - elf.GetDynamicEntryPosition(0);

    // Adjust the entry list as necessary to remove the run path
    unsigned long entriesErased = 0;
    for (cmELF::DynamicEntryList::iterator it = dentries.begin();
         it != dentries.end();) {
      if (it->first == cmELF::TagRPath || it->first == cmELF::TagRunPath) {
        it = dentries.erase(it);
        entriesErased++;
        continue;
      }
      if (cmELF::TagMipsRldMapRel != 0 &&
          it->first == cmELF::TagMipsRldMapRel) {
        // Background: debuggers need to know the "linker map" which contains
        // the addresses each dynamic object is loaded at. Most arches use
        // the DT_DEBUG tag which the dynamic linker writes to (directly) and
        // contain the location of the linker map, however on MIPS the
        // .dynamic section is always read-only so this is not possible. MIPS
        // objects instead contain a DT_MIPS_RLD_MAP tag which contains the
        // address where the dynamic linker will write to (an indirect
        // version of DT_DEBUG). Since this doesn't work when using PIE, a
        // relative equivalent was created - DT_MIPS_RLD_MAP_REL. Since this
        // version contains a relative offset, moving it changes the
        // calculated address. This may cause the dynamic linker to write
        // into memory it should not be changing.
        //
        // To fix this, we adjust the value of DT_MIPS_RLD_MAP_REL here. If
        // we move it up by n bytes, we add n bytes to the value of this tag.
        it->second += entriesErased * sizeof_dentry;
      }

      it++;
    }

    // Encode new entries list
    bytes = elf.EncodeDynamicEntries(dentries);
    bytesBegin = elf.GetDynamicEntryPosition(0);
  }

  // Open the file for update.
  std::ofstream f(file, std::ios::in | std::ios::out | std::ios::binary);
  if (!f) {
    if (emsg) {
      *emsg = "Error opening file for update.";
    }
    return false;
  }

  // Write the new DYNAMIC table header.
  if (!f.seekp(bytesBegin)) {
    if (emsg) {
      *emsg = "Error seeking to DYNAMIC table header for RPATH.";
    }
    return false;
  }
  if (!f.write(&bytes[0], bytes.size())) {
    if (emsg) {
      *emsg = "Error replacing DYNAMIC table header.";
    }
    return false;
  }

  // Fill the RPATH and RUNPATH strings with zero bytes.
  for (int i = 0; i < zeroCount; ++i) {
    if (!f.seekp(zeroPosition[i])) {
      if (emsg) {
        *emsg = "Error seeking to RPATH position.";
      }
      return false;
    }
    for (unsigned long j = 0; j < zeroSize[i]; ++j) {
      f << '\0';
    }
    if (!f) {
      if (emsg) {
        *emsg = "Error writing the empty rpath string to the file.";
      }
      return false;
    }
  }

  // Everything was updated successfully.
  if (removed) {
    *removed = true;
  }
  return true;
}

std::string::size_type cmSystemToolsFindRPath(std::string const &have,
                                              std::string const &want) {
  std::string::size_type pos = 0;
  while (pos < have.size()) {
    // Look for an occurrence of the string.
    std::string::size_type const beg = have.find(want, pos);
    if (beg == std::string::npos) {
      return std::string::npos;
    }

    // Make sure it is separated from preceding entries.
    if (beg > 0 && have[beg - 1] != ':') {
      pos = beg + 1;
      continue;
    }

    // Make sure it is separated from following entries.
    std::string::size_type const end = beg + want.size();
    if (end < have.size() && have[end] != ':') {
      pos = beg + 1;
      continue;
    }

    // Return the position of the path portion.
    return beg;
  }

  // The desired rpath was not found.
  return std::string::npos;
}
struct cmSystemToolsRPathInfo {
  unsigned long Position;
  unsigned long Size;
  std::string Name;
  std::string Value;
};

bool ChangeRPath(std::string const &file, std::string const &oldRPath,
                 std::string const &newRPath, std::string *emsg,
                 bool *changed) {
  if (changed) {
    *changed = false;
  }
  int rp_count = 0;
  bool remove_rpath = true;
  cmSystemToolsRPathInfo rp[2];
  {
    // Parse the ELF binary.
    cmELF elf(file.c_str());

    // Get the RPATH and RUNPATH entries from it.
    int se_count = 0;
    cmELF::StringEntry const *se[2] = {nullptr, nullptr};
    const char *se_name[2] = {nullptr, nullptr};
    if (cmELF::StringEntry const *se_rpath = elf.GetRPath()) {
      se[se_count] = se_rpath;
      se_name[se_count] = "RPATH";
      ++se_count;
    }
    if (cmELF::StringEntry const *se_runpath = elf.GetRunPath()) {
      se[se_count] = se_runpath;
      se_name[se_count] = "RUNPATH";
      ++se_count;
    }
    if (se_count == 0) {
      if (newRPath.empty()) {
        // The new rpath is empty and there is no rpath anyway so it is
        // okay.
        return true;
      }
      if (emsg) {
        *emsg = "No valid ELF RPATH or RUNPATH entry exists in the file; ";
        *emsg += elf.GetErrorMessage();
      }
      return false;
    }

    for (int i = 0; i < se_count; ++i) {
      // If both RPATH and RUNPATH refer to the same string literal it
      // needs to be changed only once.
      if (rp_count && rp[0].Position == se[i]->Position) {
        continue;
      }

      // Make sure the current rpath contains the old rpath.
      std::string::size_type pos =
          cmSystemToolsFindRPath(se[i]->Value, oldRPath);
      if (pos == std::string::npos) {
        // If it contains the new rpath instead then it is okay.
        if (cmSystemToolsFindRPath(se[i]->Value, newRPath) !=
            std::string::npos) {
          remove_rpath = false;
          continue;
        }
        if (emsg) {
          std::ostringstream e;
          /* clang-format off */
        e << "The current " << se_name[i] << " is:\n"
          << "  " << se[i]->Value << "\n"
          << "which does not contain:\n"
          << "  " << oldRPath << "\n"
          << "as was expected.";
          /* clang-format on */
          *emsg = e.str();
        }
        return false;
      }

      // Store information about the entry in the file.
      rp[rp_count].Position = se[i]->Position;
      rp[rp_count].Size = se[i]->Size;
      rp[rp_count].Name = se_name[i];

      std::string::size_type prefix_len = pos;

      // If oldRPath was at the end of the file's RPath, and newRPath is empty,
      // we should remove the unnecessary ':' at the end.
      if (newRPath.empty() && pos > 0 && se[i]->Value[pos - 1] == ':' &&
          pos + oldRPath.length() == se[i]->Value.length()) {
        prefix_len--;
      }

      // Construct the new value which preserves the part of the path
      // not being changed.
      rp[rp_count].Value = se[i]->Value.substr(0, prefix_len);
      rp[rp_count].Value += newRPath;
      rp[rp_count].Value += se[i]->Value.substr(pos + oldRPath.length());

      if (!rp[rp_count].Value.empty()) {
        remove_rpath = false;
      }

      // Make sure there is enough room to store the new rpath and at
      // least one null terminator.
      if (rp[rp_count].Size < rp[rp_count].Value.length() + 1) {
        if (emsg) {
          *emsg = "The replacement path is too long for the ";
          *emsg += se_name[i];
          *emsg += " entry.";
        }
        return false;
      }

      // This entry is ready for update.
      ++rp_count;
    }
  }

  // If no runtime path needs to be changed, we are done.
  if (rp_count == 0) {
    return true;
  }

  // If the resulting rpath is empty, just remove the entire entry instead.
  if (remove_rpath) {
    return RemoveRPath(file, emsg, changed);
  }

  {
    // Open the file for update.
    std::ofstream f(file, std::ios::in | std::ios::out | std::ios::binary);
    if (!f) {
      if (emsg) {
        *emsg = "Error opening file for update.";
      }
      return false;
    }

    // Store the new RPATH and RUNPATH strings.
    for (int i = 0; i < rp_count; ++i) {
      // Seek to the RPATH position.
      if (!f.seekp(rp[i].Position)) {
        if (emsg) {
          *emsg = "Error seeking to ";
          *emsg += rp[i].Name;
          *emsg += " position.";
        }
        return false;
      }

      // Write the new rpath.  Follow it with enough null terminators to
      // fill the string table entry.
      f << rp[i].Value;
      for (unsigned long j = rp[i].Value.length(); j < rp[i].Size; ++j) {
        f << '\0';
      }

      // Make sure it wrote correctly.
      if (!f) {
        if (emsg) {
          *emsg = "Error writing the new ";
          *emsg += rp[i].Name;
          *emsg += " string to the file.";
        }
        return false;
      }
    }
  }

  // Everything was updated successfully.
  if (changed) {
    *changed = true;
  }
  return true;
}

// check rpath exists.
bool CheckRPath(std::string const &file, std::string const &newRPath) {
  // Parse the ELF binary.
  cmELF elf(file.c_str());

  // Get the RPATH or RUNPATH entry from it.
  cmELF::StringEntry const *se = elf.GetRPath();
  if (!se) {
    se = elf.GetRunPath();
  }
  // Make sure the current rpath contains the new rpath.
  if (newRPath.empty()) {
    if (!se) {
      return true;
    }
  } else {
    if (se &&
        cmSystemToolsFindRPath(se->Value, newRPath) != std::string::npos) {
      return true;
    }
  }
  return false;
}
std::string LookupRPath(const std::string &file) {

  cmELF elf(file.c_str());

  // Get the RPATH or RUNPATH entry from it.
  cmELF::StringEntry const *se = elf.GetRPath();
  if (se == nullptr) {
    se = elf.GetRunPath();
  }
  if (se == nullptr) {
    return "";
  }
  return std::string(se->Value);
}
} // namespace cmake

int ReplaceRupath(const std::string &exe, const char *newrpath) {
  auto ru = cmake::LookupRPath(exe);
  if (newrpath == nullptr) {
    fprintf(stderr, "%s: RUNPATH=%s\n", exe.c_str(), ru.c_str());
    return 0;
  }
  std::string msg;
  bool changed = false;
  if (!cmake::ChangeRPath(exe, ru, newrpath, &msg, &changed)) {
    fprintf(stderr, "%s\n", msg.c_str());
    return 1;
  }
  fprintf(stderr, "%s: RUNPATH=%s\n%s: new RUNPATH: %s\n", exe.c_str(),
          ru.c_str(), exe.c_str(), newrpath);
  return 0;
}

void usage() {
  constexpr const char *kusage = R"(Usage: cmchrpath [-v|-l|-r <path>]

   -h|--help                       Display cmchrpath usage and exit.
   -v|--version                    Display cmchrpath version and exit.
   -l|--list                       List current execute rpath/rupath.
   -r <path>|--replace <path>      Replace current rpath/rupath
)";
  fprintf(stderr, "%s\n", kusage);
}

int main(int argc, char **argv) {
  const char *sopt = "?adhlr:v";
  int ch = 0;
  int opt_index = 0;
  const char *newrpath = nullptr;
  const option lopts[] = {
      ////
      {"delete", no_argument, nullptr, 'd'},
      {"help", no_argument, nullptr, 'h'},
      {"list", no_argument, nullptr, 'l'},
      {"replace", required_argument, nullptr, 'r'},
      {"version", no_argument, nullptr, 'v'},
      {nullptr, 0, nullptr, 0} ///
  };
  if (argc < 2) {
    usage();
    return 1;
  }
  while ((ch = getopt_long(argc, argv, sopt, lopts, &opt_index)) != -1) {
    switch (ch) {
    case '?':
    case 'h':
      usage();
      exit(0);
    case 'l':
      break;
    case 'r':
      newrpath = optarg;
      break;
    case 'v':
      fprintf(stderr, "1.0\n");
      exit(0);
      break;
    default:
      fprintf(stderr, "Unsupported argument: %c\n", ch);
      exit(1);
    }
  }
  int rel = 0;
  while (optind < argc) {
    /* code */
    rel |= ReplaceRupath(argv[optind++], newrpath);
  }
  return rel;
}
