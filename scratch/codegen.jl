immutable StaticBitSet
    chunks::NTuple{4, UInt64}
end

@inline _div64(l) = l >>> 6
@inline _mod64(l) = l & 63
@inline get_chunks_id(i::Integer) = _div64(Int(i)-1)+1, _mod64(Int(i)-1)

@inline function Base.in(x::UInt8, b::StaticBitSet)
    i1, i2 = get_chunks_id(x+1)
    (b.chunks[i1] & (UInt64(1) << i2)) != 0
end

function emit_level(leaf::IOTreeLeaf, args...)
    :(return $(leaf.value))
end

function emit_level(tree::Union{IOTreeRoot, IOTreeNode}, emasks, mask_idx, byte_reader, level)
    exprs = Expr(:block)
    b = gensym()
    push!(exprs.args, :($b = $(byte_reader(level))))
    cs = children(tree)
    accum_mask = copy(zeros_mask)
    for (i,c) in enumerate(cs)
        accum_mask .|= c.mask
        sm = StaticBitSet(tuple(c.mask.mask.chunks...))
        if i < length(cs)
          idx = mask_idx[sm]
          push!(exprs.args, quote
              if $b in $emasks[$idx]
                  $(emit_level(c, emasks, mask_idx, byte_reader, level+1))
              end
          end)
        else
          push!(exprs.args, emit_level(c, emasks, mask_idx, byte_reader, level+1))
        end
    end
    # Make sure the masks where exhaustive
    @assert accum_mask == ones_mask
    exprs
end

function generate_decoder_for_tree(tree, byte_reader)
    masks = Set{StaticBitSet}()
    for node in PreOrderDFS(tree)
        (node == tree) && continue
        push!(masks, StaticBitSet(tuple(node.mask.mask.chunks...)))
    end
    masks = tuple(collect(masks)...)
    mask_idx = Dict(x=>i for (i,x) in enumerate(masks))
    ret = Expr(:block)
    emasks = gensym()
    push!(ret.args, :($emasks = $masks))
    push!(ret.args, emit_level(tree, emasks, mask_idx, byte_reader, 1))
    ret
end
