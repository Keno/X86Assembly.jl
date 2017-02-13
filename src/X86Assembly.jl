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
      VADDSS xmm1,xmm2, xmm3/m32
  EVEX.NDS.LIG.F3.0F.W0 58 /r         T1S  V/V
      VADDSS xmm1{k1}{z}, xmm2, xmm3/m32{er}
"""

opcode_table = Dict{UInt8,Any}()
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
    data = (desc, ops, enc)
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
            end
            break
        end
        if contains(opcode, "+")
          base, addend = split(opcode,'+')
          opc_base = parse(UInt8, base, 16)
          for opc in opc_base:opc_base+7
            opcode_table[opc] = (strip(lines[i+1]), enc)
          end
        else
          opc = parse(UInt8, opcode, 16)
          this_opcode_table = opcode_table
          while length(opcodes) >= j+1
              j += 1
              next_opcode = opcodes[j]
              if next_opcode[1] in ['i', 'r', '/']
                  break
              end
              last_opc = opc
              opc = parse(UInt8, next_opcode, 16)
              if !haskey(this_opcode_table, last_opc)
                  this_opcode_table[last_opc] = Dict{UInt8,Any}()
              end
              this_opcode_table = this_opcode_table[last_opc]
          end
          this_opcode_table[opc] = data
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

struct Operand
    deref::Bool
    # -1%UInt8 indicates absolute
    base::UInt8
    scale::UInt8
    index::UInt8
    disp::Int32
end

struct QualifiedOperand
    # 0 - general purpose
    # 1 - vector
    # 2 - other
    category::UInt8
    mask::UInt8
    op::Operand
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
    if !op.deref
        print_reg(io, category, op.base)
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

rex_b(rex) = ((rex&0b001) << 3)
rex_x(rex) = ((rex&0b010) << 2)
rex_r(rex) = ((rex&0b100) << 1)
rex_r′(rex) = ((rex&0b10000000) >> 7)

# Returns (Reg, R/M)
function parseModRM(rex, io, evex = false)
    modrmb = read(io, UInt8)
    mod = (0b11000000 & modrmb) >> 6
    reg = (0b00111000 & modrmb) >> 3
    rm  = (0b00000111 & modrmb)
    op1 = Operand(false, reg | rex_r(rex) | rex_r′(rex), 0, 0, 0)
    if mod == 0b11
        @assert !evex || rex_x(rex) == 0
        op2 = Operand(false, rm | rex_b(rex) | (rex_x(rex) << 1), 0, 0, 0)
        return (op1, op2)
    end
    op2_base::UInt8 = rm | rex_b(rex)
    load_scale::UInt8 = 1
    disp::Int32 = 0
    sib_index::UInt8 = 0
    if rm == 0b100
        # With sib byte
        sib = read(io, UInt8)
        sib_base = (sib & 0b111)
        op2_base = sib_base | rex_b(rex)
        load_scale = 1 << ((sib & 0b11000000) >> 6)
        sib_index = (sib & 0b00111000) >> 3 | rex_x(rex)
        if sib_index == 0b11 # index = sp special case
            load_scale = 0
        end
        if mod == 0b00 && sib_base == 0b101 # base = bp special case
            disp = read(io, UInt32)%Int32
            op2_base = -1 % UInt8
        end
    end
    if mod == 0b00
        if rm == 0b101
            disp = read(data, UInt32)%Int32
            op2 = Operand(true, -1%UInt8, 1, 0, disp)
            return (op1, op2)
        end
    elseif mod == 0b01
        disp = Int32(read(io, UInt8)%Int8)
    elseif mod == 0b10
        disp = read(io, UInt32)%Int32
    end
    op2 = Operand(true, op2_base, sib_index, load_scale, disp)
    (op1, op2)
end

function parseOperands(enc,rex,vex,opc,ops,data)
    if enc == "MR"
        a,b = parseModRM(rex, data)
        (QualifiedOperand(ops[1],b), QualifiedOperand(ops[2],a))
    elseif enc == "RM"
        a,b = parseModRM(rex, data)
        (QualifiedOperand(ops[1],a), QualifiedOperand(ops[2],b))
    elseif enc == "RVM" || enc == "T1S"
        a,b = parseModRM(rex, data)
        op2 = Operand(false, vex, 0, 0, 0)
        (QualifiedOperand(ops[1],a), QualifiedOperand(ops[2],op2), QualifiedOperand(ops[3],b))
    elseif enc == "O"
        (QualifiedOperand(ops[1],
          Operand(false, (opc & 0b111)|rex_b(rex), 0%UInt8, 0%UInt8, 0%UInt32)),)
    elseif enc == "ZO"
        ()
    else
        error("Unimplemented encoding '$enc'")
    end
end

function parseOpc(data)
    rex = 0x0
    input = IOBuffer(data)
    while !eof(input)
        c = read(input, UInt8)
        if 0x40 <= c <= 0x4F
            rex = c
        elseif c == 0xc4
            @assert rex == 0
            # 3-byte VEX prefix
            V2 = read(input, UInt8)
            V3 = read(input, UInt8)
            L = UInt16((V3 & 0b100) >> 2)
            W = UInt16((V3 & 0b10000000) >> 7)
            vex_byte = ((V3 & 0b11) << 6) | (V2 & 0b1111) | L << 9 | W << 8
            fake_rex = ~((V2 & 0b11100000) >> 5)
            vvvv = ~((V3 & 0b01111000) >> 3) & 0b1111
            opc = read(input, UInt8)
            desc, ops, enc = vex_opcode_table[vex_byte][opc]
            print(STDOUT, desc, " ")
            println(STDOUT, parseOperands(enc, fake_rex, vvvv, opc, ops, input))
        elseif c == 0xc5
            @assert rex == 0
            # 2-byte VEX prefix
            V2 = read(input, UInt8)
            L = UInt16((V2 & 0b100) >> 2)
            vex_byte = ((V2 & 0b11) << 6) | 0b1 | L << 9
            fake_rex = ((~V2 & 0b10000000) >> 5)
            vvvv = ~((V2 & 0b01111000) >> 3) & 0b1111
            opc = read(input, UInt8)
            desc, ops, enc = vex_opcode_table[vex_byte][opc]
            print(STDOUT, desc, " ")
            println(STDOUT, parseOperands(enc, fake_rex, vvvv, opc, ops, input))
        elseif c == 0x62
            @assert rex == 0
            # 4-byte EVEX prefix
            P0 = read(input, UInt8)
            P1 = read(input, UInt8)
            P2 = read(input, UInt8)
            L′L = UInt16((P2 & 0b01100000) >> 5)
            W = UInt16((P1 & 0b10000000) >> 7)
            vex_byte = (P0 & 0b11) | ((P1 & 0b11) << 6) | L′L << 9 | W << 8
            # We encode R′ in the high bit of fake rex
            fake_rex = ~((P0 >> 5) | (P0 & 0b00010000) << 3)
            vvvv = (((~P1 & 0b01111000) >> 3) | ((~P2 & 0b1000) << 1))
            opc = read(input, UInt8)
            desc, ops, enc = evex_opcode_table[vex_byte][opc]
            print(STDOUT, desc, " ")
            println(STDOUT, parseOperands(enc, fake_rex, vvvv, opc, ops, input))
        else
            opc = c
            table_or_data = opcode_table[opc]
            while isa(table_or_data, Dict)
                # table, not data
                opc = read(input, UInt8)
                table_or_data = table_or_data[opc]
            end
            # data, not table
            desc, ops, enc = table_or_data
            print(STDOUT, desc, " ")
            println(STDOUT, parseOperands(enc, rex, 0, opc, ops, input))
            rex = 0x0
        end
    end
end

end # module
