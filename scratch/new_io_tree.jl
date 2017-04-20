using AbstractTrees
using AbstractTrees: ImplicitIndexStack, ImplicitNodeStack, stepstate, getnode

import AbstractTrees: children
import Base: &, <<, |, >>, ==, ~

struct ChildMask
    mask::BitVector
end
Base.copy(x::ChildMask) = ChildMask(copy(x.mask))
Base.ones(::Type{ChildMask}) = ChildMask(fill!(BitVector(256), true))
Base.broadcast(op::Union{typeof(|),typeof(&)},a::ChildMask, b::ChildMask) = ChildMask(broadcast(op,a.mask,b.mask))
Base.broadcast!(op::Union{typeof(|),typeof(&)},xs::ChildMask...) = ChildMask(broadcast!(op,map(x->x.mask, xs)...))
Base.any(m::ChildMask) = any(m.mask)
Base.broadcast(op::typeof(~),a::ChildMask) = ChildMask(broadcast(op,a.mask))
Base.:(==)(a::ChildMask, b::ChildMask) = a.mask == b.mask
Base.hash(c::ChildMask, u::UInt64) = Base.hash(c.mask, u)
Base.in(b::UInt8, c::ChildMask) = c.mask[b+1]

# Shoe the child mask using braille. One braille character per byte
function Base.show(io::IO, mask::ChildMask)
    for byte in reinterpret(UInt8, mask.mask.chunks)
        print(io, Char(0x2800+byte))
    end
end

struct IOTreeLeaf
    mask::ChildMask
    value::Any
end
function Base.showcompact(io::IO, node::IOTreeLeaf)
    Base.show(io, node.mask); print(io, ": ")
    Base.show(io, node.value)
end

struct IOTreeNode
    mask::ChildMask
    children::Vector{Union{IOTreeNode, IOTreeLeaf}}
end
Base.showcompact(io::IO, node::IOTreeNode) = Base.show(io, node.mask)
IOTreeNode(mask::ChildMask) = IOTreeNode(mask, Union{IOTreeNode, IOTreeLeaf}[])
IOTreeNode(mask::ChildMask, children::IOTreeNode) = IOTreeNode(mask, children.children)

struct IOTreeRoot
    children::Vector{Union{IOTreeNode, IOTreeLeaf}}
end
const IOTreeObject = Union{IOTreeNode, IOTreeLeaf, IOTreeRoot}
IOTreeRoot() = IOTreeRoot(IOTreeObject[])
children(tree::Union{IOTreeRoot,IOTreeNode}) = tree.children

function split!(tree, left_mask::ChildMask, right_mask::ChildMask)
    @assert !any(left_mask .& right_mask)
    total_mask = (left_mask .| right_mask)
    for (i,c) in enumerate(children(tree))
        isa(c, IOTreeLeaf) && continue
        # If the total mask is disjoint, we don't care
        any(total_mask .& c.mask) || continue
        # If the child is entirely contained within one of the masks,
        # we don't need to do anything.
        (!any(left_mask .& c.mask) ||
         !any(right_mask .& c.mask)) && continue
        # Ok, here we need to split. First, duplicate the children
        new_children = deepcopy(c.children)
        tree.children[i] = IOTreeNode(c.mask .& left_mask, c.children)
        push!(tree.children, IOTreeNode(c.mask .& right_mask, new_children))
    end
    tree
end
split!(tree, l, r) = split!(tree, ChildMask(l), ChildMask(r))


struct AbstractImmediate
  size::Int
end
Base.rem(x::AbstractImmediate, ::Type{T}) where {T} = T(0)

mutable struct GenerativeIOTree <: IO
    tree::IOTreeRoot
    state
    idx::Int
    hadImmediate::Bool
    nbytes_read::Int
end

struct AbstractBit
  # (-1%UInt8) indicates concrete
  byte_pos::UInt8
  bit_pos::UInt8
  # For concrete bits, is this 0 or 1
  set::Bool 
end

struct AbstractBitBundle{N}
  tree::Union{GenerativeIOTree, Void}
  # 1 = low bit
  abstract_bits::NTuple{N, AbstractBit}
end
const AbstractByte = AbstractBitBundle{8}

function Base.:&(x::AbstractByte, mask::UInt8)
  AbstractByte(x.tree, tuple((((mask >> (i-1)) & 1) == 1 ? x.abstract_bits[i] : concrete_bit(0) for i = 1:8)...))
end

concrete_bit(x::Integer) = (@assert x == 0 || x == 1; AbstractBit(-1%UInt8,-1%UInt8,x!=0))
isconcrete(x::AbstractBit) = x.byte_pos == -1%UInt8 && x.bit_pos == -1%UInt8
function Base.convert(::Type{AbstractByte}, x::UInt8)
  AbstractByte(nothing, tuple((concrete_bit((x >> i) & 1) for i = 0:7)...))
end
Base.convert(::Type{AbstractByte}, x::Integer) = AbstractByte(convert(UInt8, x))
Base.showcompact(io::IO, tree::IOTreeRoot) = print(io, "<Root>")

(::Type{UInt16})(x::AbstractBitBundle{N}) where {N} =
  AbstractBitBundle{16}(x.tree, tuple((i > N ? concrete_bit(0) : x.abstract_bits[i] for i = 1:16)...))


function select_bit(x, y, i)
    i > length(x.abstract_bits) && return y.abstract_bits[i]
    i > length(y.abstract_bits) && return x.abstract_bits[i]
    xbit = x.abstract_bits[i]; ybit = y.abstract_bits[i]
    (isconcrete(xbit) && xbit.set) && return xbit
    (isconcrete(ybit) && ybit.set) && return ybit
    @assert !(!isconcrete(xbit) && !isconcrete(ybit))
    isconcrete(xbit) ? ybit : xbit
end
function (|)(x::AbstractBitBundle{N}, y::AbstractBitBundle{M}) where {N,M}
  xtree = x.tree
  ytree = y.tree
  (xtree === nothing) && (xtree = ytree)
  (ytree === nothing) && (ytree = xtree)
  @assert xtree === ytree
  AbstractBitBundle{max(N,M)}(xtree, tuple((select_bit(x, y, i) for i = 1:max(N,M))...))
end
function (|)(x::AbstractBitBundle{N}, mask::Integer) where N
  AbstractBitBundle{N}(x.tree, tuple((((mask >> (i-1)) & 1) == 1 ? concrete_bit(1) : x.abstract_bits[i] for i = 1:N)...))
end
function (<<)(x::AbstractBitBundle{N}, shift::Integer) where N
  AbstractBitBundle{N}(x.tree, tuple(((i - shift >= 1) ? x.abstract_bits[i - shift] : concrete_bit(0) for i = 1:N)...))
end
function (>>)(x::AbstractBitBundle{N}, shift::Integer) where N
  AbstractBitBundle{N}(x.tree, tuple(((i + shift <= N) ? x.abstract_bits[i + shift] : concrete_bit(0) for i = 1:N)...))
end
~(x::AbstractBit) = AbstractBit(x.byte_pos, x.bit_pos, !x.set)
(~)(x::AbstractBitBundle{N}) where {N} = AbstractByte(x.tree, tuple((~x.abstract_bits[i] for i = 1:N)...))
function (&)(x::AbstractBitBundle{N}, mask::Integer) where N
  AbstractBitBundle{N}(x.tree, tuple((((mask >> (i-1)) & 1) == 1 ? x.abstract_bits[i] : concrete_bit(0) for i = 1:N)...))
end
(&)(mask::UInt8, x::AbstractByte) = x & mask

Base.rem(x::AbstractBitBundle, ::Type{UInt8}) =
  AbstractByte(x.tree, tuple((x.abstract_bits[i] for i = 1:8)...))

function descend(tree::IOTreeRoot, idxs)
    node = tree
    for idx in idxs
        node = node.children[idx]
    end
    node
end

function Base.read(tree::GenerativeIOTree, ::Type{UInt8})
    tree.idx += 1
    if tree.idx - 1 > length(tree.state.idx_stack)
        node = getnode(tree.tree, tree.state)
        isa(node, IOTreeLeaf) && @show node
        if isempty(node.children)
            new_node = IOTreeNode(ones(ChildMask), IOTreeObject[])
            push!(node.children, new_node)
        end
        # Make sure to maintain state invariants
        if !isempty(tree.state.idx_stack)
            push!(tree.state.node_stack, node)
        end
        push!(tree.state.idx_stack, 1)
    end
    tree.nbytes_read += 1
    bits = tuple((AbstractBit(tree.idx - 1, i, false) for i = 1:8)...)
    return AbstractByte(tree, bits)
end

function bitwise_mask(i)
    idxs = filter(x->(x & (UInt8(1)<<i)) != 0, 0:255)
    mask = fill!(BitVector(256), false)
    mask[idxs+1] = true
    ChildMask(mask)
end
const bitwise_masks = [bitwise_mask(i) for i = 0:7]

const ones_mask = ChildMask(fill!(BitVector(256), true))
const zeros_mask = ChildMask(fill!(BitVector(256), false))
function (==)(x::AbstractBitBundle, y::Integer)
    bits = sort(map(x->((i,b)=x; (b.byte_pos, b.bit_pos, (y & (1<<(i-1))) != 0)), enumerate(x.abstract_bits)))
    # Mask of values for which the condition is true
    mask = copy(ones_mask)
    bpos = bits[1][1]
    determined = true
    equal = true
    while true
        if isempty(bits) || (bit = shift!(bits); bit[1] != bpos)
            parent = bpos == 1 ? x.tree.tree : x.tree.state.node_stack[bpos-1]
            node = children(parent)[x.tree.state.idx_stack[bpos]]
            comb = node.mask .& mask
            if comb == node.mask
                # nothing to do
            elseif comb == zeros_mask
                equal = false
            else
                # We split this in such a way that the answer is always
                # false if we get here
                split!(parent, .~(mask), mask)
                determined = false
            end
            isempty(bits) && break
            mask = copy(ones_mask)
            bpos = bit[1]
        end
        (bpos == 0xff) && break
        mask .&= bit[3] ? bitwise_masks[bit[2]] : .~(bitwise_masks[bit[2]])
    end
    determined ? equal : false
end
(==)(x::Integer, y::AbstractBitBundle) = y == x

function Base.isless(a::AbstractBitBundle, b::Integer)
    error()
end
function Base.isless(a::Integer, b::AbstractBitBundle)
    error()
end
# TODO: Do this more efficienty
function Base.getindex(a::Dict, b::AbstractBitBundle)
    for (key, val) in a
        (key == b) && return val
    end
    error()
end
function Base.haskey(a::Dict, b::AbstractBitBundle)
    for key in keys(a)
        (key == b) && return true
    end
    return false
end
function Base.in(a::AbstractBitBundle, b::Vector)
    for x in b
        (a == x) && return true
    end
    return false
end

function next!(tree::GenerativeIOTree, v)
    parent = isempty(tree.state.node_stack) ? tree.tree : tree.state.node_stack[end]
    children(parent)[tree.state.idx_stack[end]] =
        IOTreeLeaf(children(parent)[tree.state.idx_stack[end]].mask, v)
    state = tree.state
    while true
        state = stepstate(Leaves(tree.tree), state)
        isnull(state) && return false
        state = get(state)
        !isa(getnode(tree.tree, state), IOTreeLeaf) && break
    end
    tree.state = state
    tree.idx = 1
    tree.hadImmediate = false
    tree.nbytes_read = 0
    return true
end
