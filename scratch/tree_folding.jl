function hash_subtree(node::Union{IOTreeRoot, IOTreeNode}, h::UInt64)
    for c in node.children
        h = hash(c, h)
    end
    h
end
hash_subtree(leaf::IOTreeLeaf, h::UInt64) = hash(leaf.value, h)
Base.hash(node::Union{IOTreeRoot, IOTreeNode, IOTreeLeaf}, h::UInt64) = hash_subtree(node, hash(node.mask, h))

subtree_equal(lhs::IOTreeObject, rhs::IOTreeObject) = false
subtree_equal(lhs::IOTreeLeaf, rhs::IOTreeLeaf) = lhs.value == rhs.value
function subtree_equal(lhs::Union{IOTreeRoot, IOTreeNode}, rhs::Union{IOTreeRoot, IOTreeNode})
    for (lc, rc) in zip(lhs.children, rhs.children)
        (lc == rc) || return false
    end
    return true
end

function Base.:(==)(lhs::Union{IOTreeNode, IOTreeLeaf}, rhs::Union{IOTreeNode, IOTreeLeaf})
    return false
end
function Base.:(==)(lhs::IOTreeNode, rhs::IOTreeNode)
    (lhs.mask == rhs.mask) && subtree_equal(lhs, rhs)
end
function Base.:(==)(lhs::IOTreeLeaf, rhs::IOTreeLeaf)
    (lhs.mask == rhs.mask) && lhs.value == rhs.value
end

function fold!(tree)
    hashes = map(x->x[1]=>hash_subtree(x[2], UInt64(0)), enumerate(children(tree)))
    sort!(hashes, by = x->(x[2],x[1]))
    i,j = 1,2
    while j <= length(hashes)
        if hashes[i][2] == hashes[j][2] &&
              subtree_equal(children(tree)[hashes[i][1]], children(tree)[hashes[j][1]])
            # Empty the second one, but don't delete it for now to
            # keep indices valid
            old_mask = children(tree)[hashes[j][1]].mask
            children(tree)[hashes[j][1]] = IOTreeNode(zeros_mask)
            # Merge the second one into the first
            new_mask = children(tree)[hashes[i][1]].mask .| old_mask
            children(tree)[hashes[i][1]] =             
              isa(children(tree)[hashes[i][1]], IOTreeLeaf) ?
                IOTreeLeaf(new_mask, children(tree)[hashes[i][1]].value) :
                IOTreeNode(new_mask, children(tree)[hashes[i][1]])
        else
            i = j
        end
        j += 1
    end
    filter!(c->!isa(c,IOTreeNode)||!isempty(c.children), tree.children)
    for c in children(tree)
        isa(c, IOTreeNode) && fold!(c)
    end
end
