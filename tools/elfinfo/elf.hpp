///
#ifndef KRCLI_ELF_HPP
#define KRCLI_ELF_HPP
#include <string>
#include <vector>
#include "endian.hpp"

namespace mz {

namespace endian {
enum endian_t : unsigned { None, LittleEndian, BigEndian };
}
struct elf_minutiae_t {
  std::string machine;
  std::string osabi;
  std::string soname;
  std::string rupath;
  std::string rpath; // RPATH or some
  std::string etype;
  std::vector<std::string> deps; /// require so
  endian::endian_t endian;
  int32_t version;
  bool bit64{false}; /// 64 Bit
};

class elf_memview {
public:
  elf_memview() = default;
  elf_memview(const elf_memview &) = delete;
  elf_memview &operator=(const elf_memview &) = delete;
  ~elf_memview();
  bool mapview(const std::string &file);
  bool inquisitive(elf_minutiae_t &em);
  const char *data() const { return data_; }
  size_t size() const { return size_; }
  template <typename T> T *cast(size_t off) {
    if (off >= size_) {
      return nullptr;
    }
    return reinterpret_cast<T *>(data_ + off);
  }
  template <typename Integer> Integer resive(Integer i) {
    if (!resiveable) {
      return i;
    }
    return bswap(i);
  }
  std::string stroffset(size_t off, size_t end);

private:
  bool inquisitive64(elf_minutiae_t &em);
  char *data_{nullptr};
  size_t size_{0};
  int fd{-1};
  bool resiveable{false};
};

struct AttributesTable {
  std::string name;
  std::string value;
};

struct AttributesMultiTable {
  std::string name;
  std::vector<std::string> values;
};
struct AttributesTables {
  std::vector<AttributesTable> ats;
  std::vector<AttributesMultiTable> amts;
  std::size_t mnlen{0};
  bool Empty() const { return ats.empty() && amts.empty(); }
  AttributesTables &Clear() {
    mnlen = 0;
    ats.clear();
    amts.clear();
    return *this;
  }
  AttributesTables &Append(std::string_view name, std::string_view value) {
    mnlen = (std::max)(mnlen, name.size());
    ats.emplace_back(AttributesTable{std::string(name), std::string(value)});
    return *this;
  }
  AttributesTables &Append(std::string_view name,
                           const std::vector<std::string> &value) {
    mnlen = (std::max)(mnlen, name.size());
    AttributesMultiTable amt;
    amt.name = name;
    amt.values.assign(value.begin(), value.end());
    amts.push_back(amt);
    return *this;
  }
  bool DumpWrite(FILE *file) {
    if (file == nullptr) {
      return false;
    }
    auto alignlen = mnlen + 5; //:+4
    std::string space(alignlen, ' ');
    /// ------------> Print
    for (const auto &a : ats) {
      fprintf(stderr, "%s:%.*s%s\n", a.name.c_str(),
              (int)(alignlen - a.name.size() - 1), space.data(),
              a.value.c_str());
    }
    for (const auto &am : amts) {
      if (am.values.empty()) {
        continue;
      }
      fprintf(stderr, "%s:%.*s%s\n", am.name.c_str(),
              (int)(alignlen - am.name.size() - 1), space.data(),
              am.values[0].c_str());
      auto mvsize = am.values.size();
      for (size_t i = 1; i < mvsize; i++) {
        fprintf(stderr, "%.*s%s\n", (int)alignlen, space.data(),
                am.values[i].c_str());
      }
    }
    return true;
  }
};

} // namespace mz

#endif
