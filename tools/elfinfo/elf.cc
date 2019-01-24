///

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "elf_musl.h"
#include "elf.hpp"

namespace mz {
elf_memview::~elf_memview() {
  if (data_ != nullptr) {
    ::munmap(data_, size_);
  }
  if (fd != -1) {
    close(fd);
  }
}

// mapview readonly
bool elf_memview::mapview(const std::string &file) {
  if ((fd = open(file.c_str(), O_RDONLY)) == -1) {
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    return false;
  }
  if ((size_t)st.st_size < sizeof(Elf32_Ehdr)) {
    return false;
  }
  size_ = st.st_size;
  data_ = reinterpret_cast<char *>(
      mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0));
  if (data_ == nullptr) {
    return false;
  }
  return true;
}

inline endian::endian_t Endina(uint8_t t) {
  switch (t) {
  case ELFDATANONE:
    return endian::None;
  case ELFDATA2LSB:
    return endian::LittleEndian;
  case ELFDATA2MSB:
    return endian::BigEndian;
  default:
    break;
  }
  return endian::None;
}

const char *osabi(uint8_t i) {
  switch (i) {
  case ELFOSABI_SYSV:
    return "SYSV";
  case ELFOSABI_HPUX:
    return "HP-UX";
  case ELFOSABI_NETBSD:
    return "NetBSD";
  case ELFOSABI_LINUX:
    return "Linux";
  case 4: /// musl not defined
    return "GNU Hurd";
  case ELFOSABI_SOLARIS:
    return "Solaris";
  case ELFOSABI_AIX:
    return "AIX";
  case ELFOSABI_IRIX:
    return "IRIX";
  case ELFOSABI_FREEBSD:
    return "FreeBSD";
  case ELFOSABI_TRU64:
    return "Tru64";
  case ELFOSABI_MODESTO:
    return "Novell Modesto";
  case ELFOSABI_OPENBSD:
    return "OpenBSD";
  case 0x0D:
    return "OpenVMS";
  case 0x0E:
    return "NonStop Kernel";
  case 0x0F:
    return "AROS";
  case 0x10:
    return "Fenix OS";
  case 0x11:
    return "CloudABI";
  case ELFOSABI_ARM:
    return "ARM";
  default:
    break;
  }
  return "UNKNOWN";
}
const char *Machine(uint16_t i) {
  switch (i) {
  case EM_SPARC:
    return "SPARC";
  case EM_386:
    return "x86";
  case EM_MIPS:
    return "MIPS";
  case EM_PPC:
    return "PowerPC";
  case EM_S390:
    return "S390";
  case EM_ARM:
    return "ARM";
  case EM_SH:
    return "SuperH";
  case EM_IA_64:
    return "IA-64";
  case EM_X86_64:
    return "x86-64";
  case EM_AARCH64:
    return "AArch64";
  case EM_RISCV:
    return "RISC-V";
  default:
    break;
  }
  return "UNKNOWN";
}

const char *elf_object_type(uint16_t t) {
  switch (t) {
  case ET_NONE:
    return "No file type";
  case ET_REL:
    return "Relocatable file ";
  case ET_EXEC:
    return "Executable file";
  case ET_DYN:
    return "Shared object file";
  case ET_CORE:
    return "Core file";
  }
  return "UNKNOWN";
}

std::string elf_memview::stroffset(size_t off, size_t end) {
  std::string s;
  for (size_t i = off; i < end; i++) {
    if (data_[i] == 0) {
      break;
    }
    s.push_back(data_[i]);
  }
  return s;
}

//
bool elf_memview::inquisitive64(elf_minutiae_t &em) {
  auto h = cast<Elf64_Ehdr>(0);
  if (h == nullptr) {
    return false;
  }
  em.machine = Machine(resive(h->e_machine));
  em.etype = elf_object_type(resive(h->e_type));
  auto off = resive(h->e_shoff);
  auto sects = cast<Elf64_Shdr>(off);
  auto shnum = resive(h->e_shnum);
  if (shnum * sizeof(Elf64_Shdr) + off > size_) {
    return false;
  }
  Elf64_Off sh_offset = 0;
  Elf64_Xword sh_entsize = 0;
  Elf64_Xword sh_size = 0;
  Elf64_Word sh_link = 0;
  for (Elf64_Word i = 0; i < shnum; i++) {
    auto st = resive(sects[i].sh_type);
    if (st == SHT_DYNAMIC) {
      sh_entsize = resive(sects[i].sh_entsize);
      sh_offset = resive(sects[i].sh_offset);
      sh_size = resive(sects[i].sh_size);
      sh_link = resive(sects[i].sh_link);
      continue;
    }
  }

  if (sh_offset == 0 || sh_entsize == 0 || sh_offset >= size_) {
    fprintf(stderr, "WARNING NO SECTIONS!\n");
    return true;
  }
  auto strtab = &sects[sh_link];
  if (sh_link >= shnum) {
    return false;
  }

  Elf64_Off soff = resive(strtab->sh_offset);
  Elf64_Off send = soff + resive(strtab->sh_size);
  auto n = sh_size / sh_entsize;
  auto dyn = cast<Elf64_Dyn>(sh_offset);
  for (decltype(n) i = 0; i < n; i++) {
    auto first = resive(dyn[i].d_un.d_val);
    switch (resive(dyn[i].d_tag)) {
    case DT_NEEDED: {
      auto deps = stroffset(soff + first, send);
      em.deps.push_back(deps);
    } break;
    case DT_SONAME:
      em.soname = stroffset(soff + first, send);
      break;
    case DT_RUNPATH:
      em.rupath = stroffset(soff + first, send);
      break;
    case DT_RPATH:
      em.rpath = stroffset(soff + first, send);
      break;
    default:
      break;
    }
  }

  return true;
}

bool elf_memview::inquisitive(elf_minutiae_t &em) {
  em.endian = Endina(static_cast<uint8_t>(data_[EI_DATA]));
  em.osabi = osabi(data_[EI_OSABI]);
  em.version = data_[EI_VERSION];
  auto msb = (em.endian == endian::BigEndian);
  resiveable = (msb != IsBigEndianHost);
  if (data_[EI_CLASS] == ELFCLASS64) {
    em.bit64 = true;
    return inquisitive64(em);
  }
  if (data_[EI_CLASS] != ELFCLASS32) {
    return false;
  }
  auto h = cast<Elf32_Ehdr>(0);
  em.machine = Machine(resive(h->e_machine));
  em.etype = elf_object_type(resive(h->e_type));
  auto off = resive(h->e_shoff);
  auto sects = cast<Elf32_Shdr>(off);
  auto shnum = resive(h->e_shnum);
  if (shnum * sizeof(Elf32_Shdr) + off > size_) {
    return false;
  }
  Elf32_Off sh_offset = 0;
  Elf32_Xword sh_entsize = 0;
  Elf32_Xword sh_size = 0;
  Elf32_Word sh_link = 0;
  for (Elf32_Word i = 0; i < shnum; i++) {
    auto st = resive(sects[i].sh_type);
    if (st == SHT_DYNAMIC) {
      sh_entsize = resive(sects[i].sh_entsize);
      sh_offset = resive(sects[i].sh_offset);
      sh_size = resive(sects[i].sh_size);
      sh_link = resive(sects[i].sh_link);
      continue;
    }
  }

  if (sh_offset == 0 || sh_entsize == 0 || sh_offset >= size_) {
    fprintf(stderr, "WARNING NO SECTIONS!\n");
    return true;
  }
  auto strtab = &sects[sh_link];
  if (sh_link >= shnum) {
    return false;
  }

  Elf32_Off soff = resive(strtab->sh_offset);
  Elf32_Off send = soff + resive(strtab->sh_size);
  auto n = sh_size / sh_entsize;
  auto dyn = cast<Elf32_Dyn>(sh_offset);

  for (decltype(n) i = 0; i < n; i++) {
    auto first = resive(dyn[i].d_un.d_val);
    switch (resive(dyn[i].d_tag)) {
    case DT_NEEDED: {
      auto deps = stroffset(soff + first, send);
      em.deps.push_back(deps);
    } break;
    case DT_SONAME:
      em.soname = stroffset(soff + first, send);
      break;
    case DT_RUNPATH:
      em.rupath = stroffset(soff + first, send);
      break;
    case DT_RPATH:
      em.rpath = stroffset(soff + first, send);
      break;
    default:
      break;
    }
  }
  return true;
}

} // namespace mz
