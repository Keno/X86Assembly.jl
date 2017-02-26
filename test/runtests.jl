using X86Assembly
using Base.Test

simplef = [
  0x55,                     # push   %rbp
  0x48, 0x89, 0xe5,         # mov    %rsp,%rbp
  0x89, 0x7d, 0xfc,         # mov    %edi,-0x4(%rbp)
  0x48, 0x89, 0x75, 0xf0,   # mov    %rsi,-0x10(%rbp)
  0x8b, 0x45, 0xfc,         # mov    -0x4(%rbp),%eax
  0x5d,                     # pop    %rbp
  0xc3,                     # retq
]
X86Assembly.parseAllOpc(simplef)

#=
misc = [
  0x6A, 0x01
]
X86Assembly.parseAllOpc(misc)
=#

avx = [
  0xf3,0x0f,0x58,0xed, 	    # addss	  %xmm5, %xmm5
  0xc5,0xca,0x58,0xd4,      # vaddss  %xmm4, %xmm6, %xmm2
  0xc4,0x41,0x32,0x58,0xd0,  # vaddss  %xmm8, %xmm9, %xmm10
  0x62,0x01,0x56,0x00,0x58,0xfc,  # vaddss %xmm28, %xmm21, %xmm31
  0x62,0x01,0x56,0x81,0x58,0xfc,  # vaddss %xmm28, %xmm21, %xmm31 {%k1} {z}
  0x62,0x01,0x56,0x30,0x58,0xfc  # vaddss {rd-sae}, %xmm28, %xmm21, %xmm31
]
X86Assembly.parseAllOpc(avx)

funky_prefixes = [
  0xf2,0xf3,0x0f,0x58,0xed, 	              # extra f2 prefix
  0xf2,0xf2,0xf3,0x0f,0x58,0xed, 	          # two extra f2 prefixes
  0xf2,0xf2,0xf3,0xf3,0x0f,0x58,0xed, 	    # extra f2 and f3 prefixes
  0xf2,0xf3,0xf2,0xf3,0x0f,0x58,0xed, 	    # same, but different order
  0xf3,0x66,0x0f,0x58,0xed, 	              # extraneous 66 prefix
]
X86Assembly.parseAllOpc(funky_prefixes)
