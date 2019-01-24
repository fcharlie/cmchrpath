////
#include <cstdio>
#include <cstring>
#include "elf.hpp"

int azelf(const char *file) {
  mz::elf_memview emv;
  if (!emv.mapview(file)) {
    fprintf(stderr, "mapview %s\n", strerror(errno));
    return 1;
  }
  mz::elf_minutiae_t em;
  if (!emv.inquisitive(em)) {
    fprintf(stderr, "inquisitive %s\n", strerror(errno));
    return 1;
  }
  fprintf(stderr, "File: %s\n", file);
  mz::AttributesTables ats;
  ats.Append("Address space", em.bit64 ? "64-bit" : "32-bit");
  ats.Append("Endian", em.endian == mz::endian::LittleEndian ? "LSB" : "MSB");
  std::string ver("version ");

  ats.Append("OS/ABI", std::string("version ")
                           .append(std::to_string(em.version))
                           .append(" (")
                           .append(em.osabi)
                           .append(")"));
  ats.Append("Type", em.etype);
  if (!em.rpath.empty()) {
    ats.Append("RPATH", em.rpath);
  }
  if (!em.rupath.empty()) {

    ats.Append("RUPATH", em.rupath);
  }
  if (!em.soname.empty()) {
    ats.Append("SONAME", em.soname);
  }
  if (!em.deps.empty()) {
    ats.Append("Depends", em.deps);
  }
  ats.DumpWrite(stderr);
  fprintf(stderr, "\n");
  return 0;
}

int main(int argc, char const *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s elf-file\n", argv[0]);
    return 1;
  }
  for (int i = 1; i < argc; i++) {
    azelf(argv[i]);
  }
  return 0;
}
