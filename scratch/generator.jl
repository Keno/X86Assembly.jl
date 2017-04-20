using X86Assembly
reload("X86Assembly")

mutable struct GenerativeIOTree <: IO
  stack::Vector{UInt8}
  masks::Vector{UInt8}
  idx::Int
  hadImmediate::Bool
end
GenerativeIOTree() = GenerativeIOTree(UInt8[], UInt8[], 1, false)

struct AbstractImmediate
  size::Int
end
Base.rem(x::AbstractImmediate, ::Type{T}) where {T} = T(0)

struct AbstractBit
  # (-1%UInt8) indicates concrete
  byte_pos::UInt8
  bit_pos::UInt8
  set::Bool
end

struct AbstractByte
  tree::Union{GenerativeIOTree, Void}
  # 1 = low bit
  abstract_bits::NTuple{8, AbstractBit}
end

concrete_bit(x::Integer) = (@assert x == 0 || x == 1; AbstractBit(-1%UInt8,-1%UInt8,x!=0))
isconcrete(x::AbstractBit) = x.byte_pos == -1%UInt8 && x.bit_pos == -1%UInt8
function Base.convert(::Type{AbstractByte}, x::UInt8)
  AbstractByte(nothing, tuple((concrete_bit((x >> i) & 1) for i = 0:7)...))
end
Base.convert(::Type{AbstractByte}, x::Integer) = AbstractByte(convert(UInt8, x))

X86Assembly.representative(x::Integer) = x
function X86Assembly.representative(x::AbstractByte)
  val::UInt8 = 0
  for i = 1:8
    val |= (UInt8(x.abstract_bits[i].set) << (i-1))
  end
  val
end
X86Assembly.representative(x::X86Assembly.Operand) =
  X86Assembly.Operand{UInt8, UInt32}(x.deref, X86Assembly.representative(x.base), X86Assembly.representative(x.scale),
                                              X86Assembly.representative(x.index), X86Assembly.representative(x.disp))
X86Assembly.representative(x::X86Assembly.AVX512Operand) =
  X86Assembly.AVX512Operand(
                X86Assembly.representative(x.mask),
                X86Assembly.representative(x.zero_combining),
                X86Assembly.representative(x.sae),
                X86Assembly.representative(x.er),
                X86Assembly.representative(x.rounding_mode))


function _step!(tree::GenerativeIOTree)
  # addition with carries over ignored bits
  mask = UInt16(tree.masks[end]) | UInt16(0xff) << 8
  val = UInt16(tree.stack[end] + 1)
  while (val & mask) != 0
      if (val & (UInt16(0xff) << 8)) != 0
          pop!(tree.stack)
          pop!(tree.masks)
          !isempty(tree.stack) && _step!(tree)
          return
      end
      carry = val & mask
      val &= ~mask
      val += carry << 1
  end
  tree.stack[end] = val
end

function step!(tree::GenerativeIOTree)
  tree.idx = 1
  tree.hadImmediate = false
  _step!(tree)
end

function Base.read(tree::GenerativeIOTree, ::Type{UInt8})
  @assert !tree.hadImmediate
  tree.idx += 1
  if tree.idx - 1 <= length(tree.stack)
    return AbstractByte(tree, tuple((AbstractBit(tree.idx - 1, i, ((tree.stack[tree.idx - 1] >> (i-1))&1) != 0) for i = 1:8)...))
  end
  push!(tree.stack, 1)
  push!(tree.masks, 0xff)
  bits = tuple((AbstractBit(tree.idx - 1, i, ((tree.stack[end] >> (i-1))&1) != 0) for i = 1:8)...)
  return AbstractByte(tree, bits)
end

import Base: &, <<, |, >>, ==, ~


function (&)(x::AbstractByte, mask::UInt8)
  AbstractByte(x.tree, tuple((((mask >> (i-1)) & 1) == 1 ? x.abstract_bits[i] : concrete_bit(0) for i = 1:8)...))
end
(&)(mask::UInt8, x::AbstractByte) = x & mask
function select_bit(x, y, i)
    xbit = x.abstract_bits[i]; ybit = y.abstract_bits[i]
    (isconcrete(xbit) && xbit.set) && return xbit
    (isconcrete(ybit) && ybit.set) && return ybit
    @assert !(!isconcrete(xbit) && !isconcrete(ybit))
    isconcrete(xbit) ? ybit : xbit
end
function (|)(x::AbstractByte, y::AbstractByte)
  xtree = x.tree
  ytree = y.tree
  (xtree === nothing) && (xtree = ytree)
  (ytree === nothing) && (ytree = xtree)
  @assert xtree === ytree
  AbstractByte(xtree, tuple((select_bit(x, y, i) for i = 1:8)...))
end
function (|)(x::AbstractByte, mask::UInt8)
  AbstractByte(x.tree, tuple((((mask >> (i-1)) & 1) == 1 ? concrete_bit(1) : x.abstract_bits[i] for i = 1:8)...))
end
function (<<)(x::AbstractByte, shift::Integer)
  AbstractByte(x.tree, tuple(((i - shift >= 1) ? x.abstract_bits[i - shift] : concrete_bit(0) for i = 1:8)...))
end
function (>>)(x::AbstractByte, shift::Integer)
  AbstractByte(x.tree, tuple(((i + shift <= 8) ? x.abstract_bits[i + shift] : concrete_bit(0) for i = 1:8)...))
end
~(x::AbstractBit) = AbstractBit(x.byte_pos, x.bit_pos, !x.set)
~(x::AbstractByte) = AbstractByte(x.tree, tuple((~x.abstract_bits[i] for i = 1:8)...))

const IntOrAbstract = Union{Integer, AbstractByte}
function X86Assembly.Operand(x::Bool, base::IntOrAbstract, scale::IntOrAbstract, index::IntOrAbstract, disp::T) where T
    X86Assembly.Operand{AbstractByte, T}(x, base, scale, index, disp)
end

function concretize!(x::AbstractByte)
  for bit in x.abstract_bits
    isconcrete(bit) && continue
    x.tree.masks[bit.byte_pos] &= ~(1 << (bit.bit_pos-1))
  end
  X86Assembly.representative(x)
end
X86Assembly.concretize!(x::AbstractByte) = concretize!(x)

function Base.isless(a::AbstractByte, b::Integer)
  Base.isless(concretize!(a), b)
end
function Base.isless(a::Integer, b::AbstractByte)
  Base.isless(a, concretize!(b))
end
function Base.getindex(a::Dict, b::AbstractByte)
  Base.getindex(a::Dict, concretize!(b))
end
function Base.haskey(a::Dict, b::AbstractByte)
  Base.haskey(a::Dict, concretize!(b))
end
function (==)(x::AbstractByte, y::Integer)
  concretize!(x) == y
end
(==)(x::Integer, y::AbstractByte) = y == x
(::Type{UInt16})(x::AbstractByte) = UInt16(concretize!(x))

function X86Assembly.readImmediate(tree::GenerativeIOTree, T)
  tree.hadImmediate = true
  AbstractImmediate(sizeof(T))
end
    
Base.eof(tree::GenerativeIOTree) = false

isdone(tree::GenerativeIOTree) = length(tree.stack) >= 1 && tree.stack[1] == 0xff

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

using ProgressMeter

f2f3_choices = UInt8[0x0, 0xF2, 0xF3]
function run!()
  mode = X86Assembly.processor_modes(true, true)
  n = 0
  p = Progress(1616850)
  for last_f2f3 in f2f3_choices
      for first_f2f3 in (last_f2f3 == 0 ? (UInt8(0),) : UInt8[0xF2, 0xF3])
          for last_valid_seg_prefix in UInt8[0x0, 0x64, 0x65]
              for has_lock in (true, false),
                  has_66h in (true, false),
                  has_67h in (true, false),
                  rex in [collect(0x40:0x48); 0]
                    prefix_bytes = UInt8[]
                    first_f2f3 != 0 && push!(prefix_bytes, first_f2f3)
                    (last_f2f3 != first_f2f3) && push!(prefix_bytes, last_f2f3)
                    (last_valid_seg_prefix != 0) && push!(prefix_bytes, last_valid_seg_prefix)
                    has_lock && push!(prefix_bytes, 0xF0)
                    has_66h && push!(prefix_bytes, 0x66)
                    has_67h && push!(prefix_bytes, 0x67)
                    rex != 0 && push!(prefix_bytes, rex)
                    tree = GenerativeIOTree()
                    while !isdone(tree)
                      first_non_prefix_byte = read(tree, UInt8)
                      prefix = X86Assembly.prefix_status(0x0, first_f2f3,
                        last_f2f3, last_valid_seg_prefix, has_lock, has_66h,
                        has_67h, AbstractByte(rex), first_non_prefix_byte)
                      data = X86Assembly._parseOpc(tree, prefix, mode)
                      # Invalid encoding
                      hadImmediate = tree.hadImmediate ? "..." : ""
                      if data == nothing
                          println("$([prefix_bytes; tree.stack])$hadImmediate: Invalid")
                      else
                          print("$([prefix_bytes; tree.stack])$hadImmediate: $data")
                      end
                      step!(tree)
                      next!(p)
                      n += 1
                    end
              end
          end
      end
  end
  println("Number of instruction variants: $n")
end
run!()
