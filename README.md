# X86Assembly

This is a WIP x86 disassembler. Design goals:

- No hardcoded tables. Instruction definitions are parsed from the Intel Manual.
- Performance.

Approach:
1. Parser for Intel manual. Simple disassembler that walks the tables and produces
   necessary information (in progress). Can be slow.
2. Compiler for special cases. E.g. in a lot of cases, we may only care about,
   instruction length or clobbered registers, etc. Must be fast (not yet started)
3. For 2, experiment with running the parser in 1 over, over the tree of possible
   opcode, post-composing with the transformation of interest and generating
   instructions from that.
