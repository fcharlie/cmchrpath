
add_executable(cmchrpath
  cmchrpath.cc
  cmELF.cxx
)


target_link_libraries(cmchrpath
  -static-libstdc++
  -static-libgcc
)


install(TARGETS cmchrpath
    DESTINATION bin
)
