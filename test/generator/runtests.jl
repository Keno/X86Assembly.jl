using Base.Test
using AbstractTrees

function runtest_leaves(f, masks = false)
    root = IOTreeRoot()
    t = GenerativeIOTree(root, AbstractTrees.firststate(Leaves(root)), 1)
    while true
        show(STDOUT, Tree(t.tree))
        next!(t, f(t)) || break
    end
    show(STDOUT, Tree(t.tree))
    !masks ? collect(map(x->x.value, Leaves(t.tree))) :
            collect(map(x->x.mask=>x.value, Leaves(t.tree)))
end

# Simple splitting on the third byte
function parse_simple(io)
    a = read(io, UInt8)
    b = read(io, UInt8)
    c = read(io, UInt8)
    return (c & (UInt8(1) << 4)) == 0
end
@test runtest_leaves(parse_simple, true) == [bitwise_masks[5]=>false, .~(bitwise_masks[5])=>true]

function parse_multiple(io)
    a = read(io, UInt8)
    b = read(io, UInt8)
    c = read(io, UInt8)
    return c == 0x42
end
z = fill!(BitVector(256), false)
z[0x42+1] = 1
@test runtest_leaves(parse_multiple, true) == [ChildMask(.~(z))=>false, ChildMask(z)=>true]

# Simple splitting, but on an earlier byte
function parse_early(io)
    a = read(io, UInt8)
    b = read(io, UInt8)
    c = read(io, UInt8)
    return (c & (UInt8(1) << 4)) == 0 && (a & (UInt8(1) << 2)) == 0
end
runtest_leaves(parse_early, true)

# Just reading the first byte
function parse_first(io)
    a = read(io, UInt8)
    return false
end
runtest_leaves(parse_first, true)

# Just reading the first byte, but actually using it in the decision
function parse_first_decision(io)
    a = read(io, UInt8)
    return (a & (UInt8(1) << 4)) == 0 && (a & (UInt8(1) << 2)) == 0
end
runtest_leaves(parse_first_decision, true)
