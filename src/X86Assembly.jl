module X86Assembly

data = """
PUSH:
  FF /6               M   V/V
    PUSH r/m16
  FF /6               M   N/V
    PUSH r/m32
  FF /6               M   V/N
    PUSH r/m64
  50+rw               O   V/V
    PUSH r16
  50+rd               O   N/V
    PUSH r32
  50+rd               O   V/N
    PUSH r64
  6A ib               I   V/V
    PUSH imm8
  68 iw               I   V/V
    PUSH imm16
  68 id               I   V/V
    PUSH imm32
  0E                  ZO  I/V
    PUSH CS
  16                  ZO  I/V
    PUSH SS
  1E                  ZO  I/V
    PUSH DS
  06                  ZO  I/V
    PUSH ES
  0F A0               ZO  V/V
    PUSH FS
  0F A8               ZO  V/V
    PUSH GS
POP:
  8F /0               M   V/V
    POP r/m16
  8F /0               M   N/V
    POP r/m32
  8F /0               M   V/N
    POP r/m64
  58+rw               O   V/V
    POP r16
  58+rd               O   N/V
    POP r32
  58+rd               O   V/N
    POP r64
  1F                  ZO  I/V
    POP DS
  07                  ZO  I/V
    POP ES
  17                  ZO  I/V
    POP SS
  0F A1               ZO  V/V
    POP FS
  0F A1               ZO  N/V
    POP FS
  0F A1               ZO  V/N
    POP FS
  0F A9               ZO  V/V
    POP GS
  0F A9               ZO  N/V
    POP GS
  0F A9               ZO  V/N
    POP GS
MOV:
  88 /r               MR  V/V
    MOV r/m8, r8
  REX 88 /r           MR  V/N
    MOV r/m8, r8
  89 /r               MR  V/V
    MOV r/m16, r16
  89 /r               MR  V/V
    MOV r/m32, r32
  REX.W 89 /r         MR  V/N
    MOV r/m64, r64
  8A /r               RM  V/V
    MOV r8,r/m8
  REX 8A /r           RM  V/N
      MOV r8,r/m8
  8B /r               RM  V/V
      MOV r16,r/m16
  8B /r               RM  V/V
      MOV r32,r/m32
  REX.W 8B /r         RM  V/V
      MOV r64,r/m64
  8C /r               MR  V/V
      MOV r/m16,Sreg
  REX.W 8C /r         MR  V/V
      MOV r/m64,Sreg
  8E /r               RM  V/V
      MOV Sreg,r/m16
  REX.W 8E /r         RM  V/V
      MOV Sreg,r/m64
  A0                  FD  V/V
      MOV AL,moffs8
  REX.W A0            FD  V/N
      MOV AL,moffs8
  A1                  FD  V/V
      MOV AX,moffs16
  A1                  FD  V/V
      MOV EAX,moffs32
  REX.W A1            FD  V/N
      MOV RAX,moffs64
  A2                  TD  V/V
      MOV moffs8,AL
  REX.W A2            TD  V/N
      MOV moffs8,AL
  A3                  TD  V/V
      MOV moffs16,AX
  A3                  TD  V/V
      MOV moffs32,EAX
  REX.W A3            TD  V/N
      MOV moffs64,RAX
  B0 rb ib            OI  V/V
      MOV r8, imm8
  REX B0 rb ib        OI  V/N
      MOV r8, imm8
  B8 rw iw            OI  V/V
      MOV r16, imm16
  B8 rd id            OI  V/V
      MOV r32, imm32
  REX.W B8 rd io      OI  V/N
      MOV r64, imm64
  C6 /0 ib            MI  V/V
      MOV r/m8, imm8
  REX C6 /0 ib        MI  V/N
      MOV r/m8, imm8
  C7 /0 iw            MI  V/V
      MOV r/m16, imm16
  C7 /0 id            MI  V/V
      MOV r/m32, imm32
  REX.W C7 /0 id      MI  V/N
      MOV r/m64, imm32
RET:
  C3                  ZO  V/V
      RET
  CB                  ZO  V/V
      RET
  C2 iw               I   V/V
      RET imm16
  CA iw               I   V/V
      RET imm16
ADDSS:
  F3 0F 58 /r                         RM   V/V
      ADDSS xmm1, xmm2/m32
  VEX.NDS.128.F3.0F.WIG 58 /r         RVM  V/V
      VADDSS xmm1, xmm2, xmm3/m32
  EVEX.NDS.LIG.F3.0F.W0 58 /r         T1S  V/V
      VADDSS xmm1{k1}{z}, xmm2, xmm3/m32{er}
"""

# Corner cases:
# Q: What happens when there's an optional prefix after a mandatory prefix?
#     e.g. F3 66 0F 58 ED
# A: Get's decoded as as if prefixes reversed
#
# Q: Can an instruction meaningfully have more than one group 1 prefix?
#     e.g. F0 F2 64 83 0C 25 08 03 00 00 10 or
#          F2 F0 64 83 0C 25 08 03 00 00 10 or
# A: Yes, this gets interpreted as xacquire/xrelease
#
# Q: What happens with multiple group 2 prefixes?
#     e.g. 0x26 0x2e 0x8b 0x45 0x20
#       or 0x2e 0x26 0x8b 0x45 0x20
# A: The prefix closest to the opcode prevails
#
# Q: What happens when mandatory prefixes are in conflict?
#     e.g. 0xF2 0x66 0x0F 0x12 0xED vs
#          0x66 0xF2 0x0F 0x12 0xED
#
# A: F2/F3 Takes precedence
#
# Q: What happens with legacy prefixes on (E)VEX instructions?
#
# See architecture manual Vol 2. Prefixes LOCK, 66/F2/F3, REX will #UD,
# segment overrides and 67h are allowed

struct InstrProperties
    # Has support for embedded rounding control
    er::Bool
    # Has support for suppress-all-exceptions
    sae::Bool
    # Has support for zero-merging option
    z::Bool
    # Has support for masking
    masking::Bool
    # Operand encoding category
    enc::String
end

basic_table = Dict{UInt8,Any}()
table_f20f = Dict{UInt8,Any}()
table_f30f = Dict{UInt8,Any}()
table_660f = Dict{UInt8,Any}()

# First level is indexed by vex 11 bits:
# L'LWppmmmm
const vex_opcode_table = Dict{UInt16,Any}()
const evex_opcode_table = Dict{UInt16,Any}()
lines = split(data, '\n')
i = 1

function add_to_table!(table, vex_byte, opc, data)
    if !haskey(table, vex_byte)
        table[vex_byte] = Dict{UInt8,Any}()
    end
    table[vex_byte][opc] = data
end

function add_to_table_W!(table, base_vex, opc, data, W)
    if W in ["W0", "WIG"]
        add_to_table!(table, base_vex, opc, data)
    end
    if W in ["W1", "WIG"]
        add_to_table!(table, base_vex | (1 << 8), opc, data)
    end
end

while i <= length(lines)
    line = lines[i]
    isempty(line) && (i += 1; continue)
    if line[1] != ' '
        i += 1; continue
    end
    range = search(line, "  ", 3)
    opcodes = split(strip(line[1:first(range)-1], ' '), ' ')
    enc  = split(strip(line[last(range)+1:end]),' ')[1]
    desc = strip(lines[i+1])
    j = 1
    begin
      idx = findfirst(desc, ' ')
      ops = map(strip, split(desc[idx+1:end], ','))
      ops = map(ops) do op
          op[1] == 'r' ? 0 :
          op[1] == 'x' ? 1 :
          2
      end
    end
    er = contains(desc, "{er}")
    sae = contains(desc, "{sae}") || contains(desc, "{er}")
    z = contains(desc, "{z}")
    masking = contains(desc, "{k1}")
    data = (desc, ops, InstrProperties(er, sae, z, masking, enc))
    while true
        opcode = opcodes[j]
        if startswith(opcode, "REX")
            j += 1
            continue
        end
        if startswith(opcode, "VEX") || startswith(opcode, "EVEX")
            parts = split(opcode, '.')
            @assert parts[1] in ["VEX", "EVEX"]
            @assert parts[2] in ["NDS","NDD","DDS"]
            @assert (parts[1] == "EVEX" && parts[3] == "512") ||
              parts[3] in ["128","256","LIG"]
            @assert parts[4] in ["66","F2","F3"]
            @assert parts[5] in ["0F","0F3A","0F38"]
            @assert parts[6] in ["W0","W1","WIG"]
            base_vex =  parts[4] == "66" ? 0b01000000 :
                        parts[4] == "F3" ? 0b10000000 :
                                           0b11000000
            base_vex |= parts[5] == "0F" ?       0b01 :
                        parts[5] == "0F3A" ?     0b11 :
                                                 0b10
            j += 1
            opc = parse(Int, opcodes[j], 16)
            table = parts[1] == "EVEX" ? evex_opcode_table : vex_opcode_table
            if parts[3] in ["128","LIG"]
                add_to_table_W!(table, base_vex, opc, data, parts[6])
            end
            if parts[3] in ["256","LIG"]
                add_to_table_W!(table, base_vex | (1<<9), opc, data, parts[6])
            end
            if (parts[1] == "EVEX") && parts[3] in ["512","LIG"]
                add_to_table_W!(table, base_vex | (0b10<<9), opc, data, parts[6])
                add_to_table_W!(table, base_vex | (0b11<<9), opc, data, parts[6])
            end
            break
        end
        if contains(opcode, "+")
          base, addend = split(opcode,'+')
          opc_base = parse(UInt8, base, 16)
          for opc in opc_base:opc_base+7
            basic_table[opc] = data
          end
        else
          opc = parse(UInt8, opcode, 16)
          this_opcode_table = basic_table
          at_start = true
          while length(opcodes) >= j+1
              j += 1
              next_opcode = opcodes[j]
              if next_opcode[1] in ['i', 'r', '/']
                  break
              end
              last_opc = opc
              opc = parse(UInt8, next_opcode, 16)
              # Mandatory prefixes
              if at_start && (last_opc == 0xF2 || last_opc == 0xF3 || last_opc == 0x66)
                  @assert opc == 0x0F
                  this_opcode_table = last_opc == 0xF2 ? table_f20f :
                                      last_opc == 0xF3 ? table_f30f :
                                                         table_660f
                  j += 1
                  opc = parse(UInt8, opcodes[j], 16)
                  at_start = false
                  continue
              end
              at_start = false
              if !haskey(this_opcode_table, last_opc)
                  this_opcode_table[last_opc] = Dict{UInt8,Any}()
              end
              this_opcode_table = this_opcode_table[last_opc]
          end
          if opcodes[j] != "/0" && opcodes[j] != "/6" # Skip for now
            this_opcode_table[opc] = data
          end
        end
        break
    end
    i += 2
end


simplef = [
  0x55,                     # push   %rbp
  0x48, 0x89, 0xe5,         # mov    %rsp,%rbp
  0x89, 0x7d, 0xfc,         # mov    %edi,-0x4(%rbp)
  0x48, 0x89, 0x75, 0xf0,   # mov    %rsi,-0x10(%rbp)
  0x8b, 0x45, 0xfc,         # mov    -0x4(%rbp),%eax
  0x5d,                     # pop    %rbp
  0xc3,                     # retq
]

struct Operand{S, T}
    deref::Bool
    # -1%UInt8 indicates absolute
    base::S
    scale::S
    index::S
    disp::T
end
representative(op::Operand{UInt8, <:Integer}) = op

struct QualifiedOperand
    # 0 - general purpose
    # 1 - vector
    # 2 - other
    category::UInt8
    op::Operand
end

struct AVX512Operand
    # (-1)%UInt8: None by instr def
    mask
    zero_combining
    # Suppres all exceptions
    sae
    # Static round overwrite
    er
    rounding_mode
end
representative(op::AVX512Operand) = op

function Base.show(io::IO, op::AVX512Operand)
    op = representative(op)
    (op.mask != -1%UInt8 && op.mask != 0) && print(io, "{k",op.mask,"}")
    op.zero_combining != 0 && print(io, "{z}")
    if op.er != 0
      @assert op.rounding_mode <= 0b11
      print(io, op.rounding_mode == 0b00 ? "{rn-sae}" :
                  op.rounding_mode == 0b01 ? "{rd-sae}" :
                  op.rounding_mode == 0b10 ? "{ru-sae}" :
                                             "{rz-sae}")
    elseif op.sae != 0
        print(io, "{sae}")
    end
end

gpregs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

function print_reg(io::IO, category, reg)
    if category == 0
        print(io, gpregs[reg+1])
    elseif category == 1
        print(io, "xmm$reg")
    else
        print(io, "<unknown register category>")
    end
end
          
function Base.show(io::IO, op::Operand, category=0)
    op = representative(op)
    if !op.deref
        print_reg(io, category, op.base)
    elseif op.base == -1%UInt8
        print(io, "[", op.disp, "]")
    else
        print(io, "(")
        print_reg(io, category, op.base)
        print(io, " ", op.scale, "*")
        print_reg(io, category, op.index)
        print(io, " + ", op.disp, ")")
    end
end

function Base.show(io::IO, op::QualifiedOperand)
    show(io, op.op, op.category)
end

macro invalid(reason)
    :(return nothing)
end

# This is produced by the (hand-coded) fast prefix decoder and consumed by
# the general instruction decoder
struct prefix_status{T}
    nprefix_bytes::UInt8
    first_f2f3::UInt8
    last_f2f3::UInt8
    last_valid_seg_prefix::UInt8
    has_lock::Bool
    has_66h::Bool
    has_67h::Bool
    rex::T
    first_non_prefix_byte::T
end

# Compress prefix flags into a bitwise representation
#
# ffllssso67rrrrr
#  | |\|/|||\_ REX bytes, 0 = no prefix, 1X for 0x4X
#  | | | ||\__ Saw 0x67 prefix
#  | | | |\___ Saw 0x66 prefix
#  | | | \____ Saw LOCK prefix
#  | | \______ Last valid segment prefix:
#  | |          000: None
#  | |          001: 0x2E  010: 0x26
#  | |          011: 0x3E  100: 0x36
#  | |          101: 0x64  110: 0x65
#  | \________ Last F2/F3 Prefix (0: none; 01: F2; 10: F3)
#  \__________ First F2/F3 Prefix (0: none; 01: F2; 10: F3)

struct compressed_prefix_status{T,S}
    nprefix_bytes::UInt8
    flags::T
    first_non_prefix_byte::S
end

rex_bits(c) = c.flags & 0b11111
sssbits(c) = (c.flags >> 8) & 0b111
last_f2f3(c) = (c.flags >> 11) & 0b11
first_f2f3(c) = (c.flags >> 13) & 0b11
function validate_compressed_prefix(c)
    if rex_bits(c) in collect(0x1:0x8)
        return false
    elseif sssbits(c) == 0b111
        return false
    elseif last_f2f3(c) == 0b11 || first_f2f3(c) == 0b11 || (
        (last_f2f3(c) == 0 && first_f2f3(c) != 0) ||        
        (first_f2f3(c) == 0 && last_f2f3(c) != 0)
      )
        return false
    end
    return true
end

const MAX_INSTR_BYTES = 15

compress_f2f3(f2f3) = f2f3 == 0xf2 ? 0b01 :
                      f2f3 == 0xf3 ? 0b10 :
                                     0b00

compress_seg_prefix(sp) = sp == 0x00 ? 0b000 :
                          sp == 0x2E ? 0b001 :
                          sp == 0x26 ? 0b010 :
                          sp == 0x3E ? 0b011 :
                          sp == 0x36 ? 0b100 :
                          sp == 0x64 ? 0b101 :
                          sp == 0x65 ? 0b110 :
                          error()


function compressed_prefix_status(nprefix_bytes, first_f2f3, last_f2f3, last_valid_seg_prefix,
              has_lock, has_66h, has_67h, rex, first_non_prefix_byte)
    flags = UInt16(compress_f2f3(first_f2f3))                     << 13 |
            UInt16(compress_f2f3(last_f2f3))                      << 11 |
            UInt16(compress_seg_prefix(last_valid_seg_prefix))    <<  8 |
            UInt8(has_lock)                                       <<  7 |
            UInt8(has_66h)                                        <<  6 |
            UInt8(has_67h)                                        <<  5 |
            (rex & 0xF0) >> 2  | (rex & 0x0F)
    compressed_prefix_status(nprefix_bytes, flags, first_non_prefix_byte)
end

# This is shared between the fast and the slow path - performance matters
@inline function _fast_prefix_scanner(prefix_status, input, mode)
    nprefix_bytes::UInt8 = 0
    first_f2f3::UInt8 = 0
    last_f2f3::UInt8 = 0
    last_valid_seg_prefix::UInt8 = 0
    has_lock::Bool = 0
    has_66h::Bool = false
    has_67h::Bool = false
    rex::UInt8 = 0
    first_non_prefix_byte::UInt8 = 0
    @assert mode.Lflag
    while !eof(input) && nprefix_bytes < MAX_INSTR_BYTES
        c::UInt8 = read(input, UInt8)
        if c == 0x66
            # Operand size override prefix
            has_66h = true
            rex = 0
        elseif c == 0x67
            # Address size override prefix
            has_67h = true
            rex = 0
        elseif c == 0x2E || c == 0x3E || c == 0x26 || c == 0x36
            # Legacy segment prefixes - ignored in 64bit mode
            !(mode.Lflag) && (last_valid_seg_prefix = c)
            rex = 0
        elseif c == 0x64 || c == 0x65
            last_valid_seg_prefix = c
            rex = 0
        elseif c == 0xF0
            has_lock = true
            rex = 0
        elseif c == 0xF2 || c == 0xF3
            first_f2f3 == 0 && (first_f2f3 = c)
            last_f2f3 = c
        elseif mode.Lflag && 0x40 <= c <= 0x4F
            rex = c
        else
            first_non_prefix_byte = c
            break
        end
    end
    prefix_status(nprefix_bytes, first_f2f3, last_f2f3, last_valid_seg_prefix,
                  has_lock, has_66h, has_67h, rex, first_non_prefix_byte)
end
function fast_compressed_prefix_scanner(io, mode = processor_modes(true,true))
    _fast_prefix_scanner(compressed_prefix_status, io, mode)
end
fast_prefix_scanner(io, mode = processor_modes(true, true)) =
    _fast_prefix_scanner(prefix_status, io, mode)


rex_w(rex) = (rex & 0b1000)
rex_b(rex) = ((rex&0b001) << 3)
rex_x(rex) = ((rex&0b010) << 2)
rex_r(rex) = ((rex&0b100) << 1)
rex_r′(rex) = ((rex&0b10000000) >> 4)

readImmediate(input::IO, T) = read(input, T)

# Returns (Reg, R/M)
function parseModRM(rex, io, evex = false)
    modrmb = read(io, UInt8)
    mod = (0b11000000 & modrmb) >> 6
    reg = (0b00111000 & modrmb) >> 3
    rm  = (0b00000111 & modrmb)
    op1 = Operand(false, reg | rex_r(rex) | (rex_r′(rex) << 1), UInt8(0), UInt8(0), 0)
    if mod == 0b11
        (evex || rex_x(rex) == 0) || @invalid "Only allowed with evex encoding"
        op2 = Operand(false, rm | rex_b(rex) | (rex_x(rex) << 1), UInt8(0), UInt8(0), 0)
        return (op1, op2)
    end
    op2_base::typeof(rm) = rm | rex_b(rex)
    load_scale::typeof(rm) = 1
    disp::Int32 = 0
    sib_index::typeof(rm) = 0
    if rm == 0b100
        # With sib byte
        sib = read(io, UInt8)
        sib_base = (sib & 0b111)
        op2_base = sib_base | rex_b(rex)
        load_scale = ((sib & 0b11000000) >> 6)
        sib_index = (sib & 0b00111000) >> 3 | rex_x(rex)
        if sib_index == 0b11 # index = sp special case
            load_scale = 0
        end
        if mod == 0b00 && sib_base == 0b101 # base = bp special case
            disp = readImmediate(io, UInt32)%Int32
            op2_base = -1 % UInt8
        end
    end
    if mod == 0b00
        if rm == 0b101
            disp = readImmediate(io, UInt32)%Int32
            op2 = Operand(true, -1%UInt8, 1, 0, disp)
            return (op1, op2)
        end
    elseif mod == 0b01
        disp = Int32(readImmediate(io, UInt8)%Int8)
    elseif mod == 0b10
        disp = readImmediate(io, UInt32)%Int32
    end
    op2 = Operand(true, op2_base, sib_index, load_scale, disp)
    (op1, op2)
end

macro maybe(expr)
    x = gensym()
    esc(quote
        $x = $expr
        $x === nothing && return nothing
        $x
    end)
end

function parseOperands(enc,rex,vex,opc,ops,data,evex)
    if enc == "MR"
        a,b = @maybe parseModRM(rex, data, evex)
        (QualifiedOperand(ops[1],b), QualifiedOperand(ops[2],a))
    elseif enc == "RM"
        a,b = @maybe parseModRM(rex, data, evex)
        (QualifiedOperand(ops[1],a), QualifiedOperand(ops[2],b))
    elseif enc == "RVM" || enc == "T1S"
        a,b = @maybe parseModRM(rex, data, evex)
        op2 = Operand(false, vex, UInt8(0), UInt8(0), 0)
        (QualifiedOperand(ops[1],a), QualifiedOperand(ops[2],op2), QualifiedOperand(ops[3],b))
    elseif enc == "O"
        (QualifiedOperand(ops[1],
          Operand(false, (opc & 0b111)|rex_b(rex), 0%UInt8, 0%UInt8, 0%UInt32)),)
    elseif enc == "OI"
      (QualifiedOperand(ops[1],
        Operand(false, (opc & 0b111)|rex_b(rex), 0%UInt8, 0%UInt8, 0%UInt32)),
        readImmediate(data, UInt32))
    elseif enc == "ZO"
        ()
    elseif enc == "FD" || enc == "TD"
        #TODO: These two are wrong
        (readImmediate(data, UInt32),)
    elseif enc == "I"
        (readImmediate(data, UInt32),)
    else
        error("Unimplemented encoding '$enc'")
    end
end

struct processor_modes
    Dflag::Bool
    Lflag::Bool
end

had_f2f3(prefix) = prefix.last_f2f3 != 0
had_f2f3(prefix::compressed_prefix_status) = last_f2f3(prefix) != 0
had_66(prefix) = prefix.has_66h
had_66(prefix::compressed_prefix_status) = ((prefix.flags >> 6) & 0b1) != 0
was_lastf2(prefix) = prefix.last_f2f3 == 0xF2
was_lastf2(prefix::compressed_prefix_status) = last_f2f3(prefix) == 0b01
was_lastf3(prefix) = prefix.last_f2f3 == 0xF3
was_lastf3(prefix::compressed_prefix_status) = last_f2f3(prefix) == 0b10
make_rex(prefix) = prefix.rex
make_rex(prefix::compressed_prefix_status) = (rex_bits(prefix) | ((rex_bits(prefix) & 0b10000) << 2)) % UInt8

function dispatch_simple_op(input, prefix, opc)
    table = basic_table
    next_opc::typeof(opc) = 0
    if opc == 0x0F && (had_f2f3(prefix) != 0 || had_66(prefix))
        next_opc = read(input, UInt8)
        table = table[opc]
        if was_lastf2(prefix)
            if haskey(table_f20f, next_opc)
                table = table_f20f
            end
        elseif was_lastf3(prefix)  
            if haskey(table_f30f, next_opc)
                table = table_f30f
            end
        elseif had_66(prefix)
            if haskey(table_660f, next_opc)
                table = table_660f
            end
        end
        opc = next_opc
    end
    !haskey(table, opc) && @invalid "Opcode not in table"
    table_or_data = table[opc]
    while isa(table_or_data, Dict)
        # table, not data
        opc = read(input, UInt8)
        !haskey(table_or_data, opc) && @invalid "Opcode not in table"
        table_or_data = table_or_data[opc]
    end
    # data, not table
    desc, ops, data = table_or_data
    operands = @maybe parseOperands(data.enc, make_rex(prefix), 0, opc, ops, input, false)
    return sprint() do io
      print(io, desc, " ")
      println(io, operands)
    end
end

concretize!(x::UInt8) = x

parseOpc(data::Vector{UInt8}, mode = processor_modes(true,true)) =
  parseOpc(IOBuffer(data), mode)


  
function parseOpc(input::IO, mode = processor_modes(true,true))
    # Only supported for far
    @assert mode.Lflag
    operand_size = 4
    address_size = 8
    prefix_status = fast_prefix_scanner(input)
    _parseOpc(input, prefix_status, mode)
end

function validate_legacy_prefixes_for_vex(prefix)
    prefix.last_f2f3 == 0 || @invalid "No legacy prefixes allowed with (e)vex"
    !prefix.has_66h || @invalid "No operand size override allowed with (e)vex"
    !prefix.has_lock || @invalid "No lock prefix allowed with (e)vex"
    prefix.rex == 0 || @invalid "No REX prefix allowed with (e)vex"
    true
end

function validate_legacy_prefixes_for_vex(prefix::compressed_prefix_status)
    #                 ffllssso67rrrrr
    (prefix.flags & 0b111100011011111) == 0 || @invalid "Disallowed prefixes"
    true
end

function _parseOpc(input::IO, prefix, mode)
    c = prefix.first_non_prefix_byte
    if c == 0xc4
        @maybe validate_legacy_prefixes_for_vex(prefix)
        # 3-byte VEX prefix
        V2 = read(input, UInt8)
        (V2 & 0b1100 == 0) || @invalid "Invalid value for mmmm"
        V3 = read(input, UInt8)
        L = UInt16((V3 & 0b100) >> 2)
        W = UInt16((V3 & 0b10000000) >> 7)
        vex_byte = UInt16((V3 & 0b11) << 6) | UInt16(V2 & 0b0011) | L << 9 | W << 8
        fake_rex = ~((V2 & 0b11100000) >> 5)
        vvvv = ~((V3 & 0b01111000) >> 3) & 0b1111
        opc =  read(input, UInt8)
        # Our generation scheme is naive and doesn't realize that rex_x
        # matters. Tell it manually for now.
        haskey(vex_opcode_table, vex_byte) || @invalid "Invalid opcode"
        haskey(vex_opcode_table[vex_byte], opc) || @invalid "Invalid opcode"
        desc, ops, data = vex_opcode_table[vex_byte][opc]
        operands = @maybe parseOperands(data.enc, fake_rex, vvvv, opc, ops, input, false)
        return sprint() do io
          print(io, desc, " ")
          println(io, operands)
        end
    elseif c == 0xc5
        @maybe validate_legacy_prefixes_for_vex(prefix)
        # 2-byte VEX prefix
        V2 = read(input, UInt8)
        L = UInt16((V2 & 0b100) >> 2)
        vex_byte = UInt16((V2 & 0b11) << 6) | 0b1 | L << 9
        fake_rex = ((~V2 & 0b10000000) >> 5)
        vvvv = ~((V2 & 0b01111000) >> 3) & 0b1111
        opc = read(input, UInt8)
        # Our generation scheme is naive and doesn't realize that rex_x
        # matters. Tell it manually for now.
        haskey(vex_opcode_table, vex_byte) || @invalid "Invalid opcode"
        haskey(vex_opcode_table[vex_byte], opc) || @invalid "Invalid opcode"
        desc, ops, data = vex_opcode_table[vex_byte][opc]
        operands = @maybe parseOperands(data.enc, fake_rex, vvvv, opc, ops, input, false)
        return sprint() do io
          print(io, desc, " ")
          println(io, operands)
        end
    elseif c == 0x62
        @maybe validate_legacy_prefixes_for_vex(prefix)
        # 4-byte EVEX prefix
        P0 = read(input, UInt8)
        P1 = read(input, UInt8)
        P2 = read(input, UInt8)
        z = (P2 & 0b10000000) >> 7
        b = (P2 & 0b00010000) >> 4
        aaa = (P2 & 0b00000111)
        L′L = UInt16((P2 & 0b01100000) >> 5)
        W = UInt16((P1 & 0b10000000) >> 7)
        vex_byte = UInt16(P0 & 0b11) | UInt16((P1 & 0b11) << 6) | L′L << 9 | W << 8
        # We encode R′ in the high bit of fake rex
        fake_rex = ~((P0 >> 5) | (P0 & 0b00010000) << 3)
        vvvv = (((~P1 & 0b01111000) >> 3) | ((~P2 & 0b1000) << 1))
        opc = read(input, UInt8)
        haskey(evex_opcode_table, vex_byte) || @invalid "Invalid opcode"
        haskey(evex_opcode_table[vex_byte], opc) || @invalid "Invalid opcode"
        desc, ops, data = evex_opcode_table[vex_byte][opc]
        avx512o = AVX512Operand(aaa, z, (UInt8(data.sae) & b), (UInt8(data.er) & b),
          ((UInt8(data.er) & b) != 0) ? L′L : 0)
        operands = @maybe parseOperands(data.enc, fake_rex, vvvv, opc, ops, input, true)
        return sprint() do io
          print(io, desc, " ")
          println(io, tuple(avx512o, operands...))
        end
    else
        return dispatch_simple_op(input, prefix, c)
    end
    return nothing
end

parseAllOpc(data::Vector{UInt8}) = parseAllOpc(IOBuffer(data))
function parseAllOpc(input::IO)
    while !eof(input)
        x = parseOpc(input)
        @assert x !== nothing
        println(x)
    end
end

end # module
