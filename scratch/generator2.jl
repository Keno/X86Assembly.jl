include("new_io_tree.jl")
using X86Assembly

X86Assembly.representative(x::Integer) = x
function X86Assembly.representative(x::AbstractBitBundle)
  val::UInt8 = 0
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

const IntOrAbstract = Union{Integer, AbstractByte}
function X86Assembly.Operand(x::Bool, base::IntOrAbstract, scale::IntOrAbstract, index::IntOrAbstract, disp::T) where T
    X86Assembly.Operand{AbstractByte, T}(x, base, scale, index, disp)
end

function X86Assembly.readImmediate(tree::GenerativeIOTree, T)
  tree.hadImmediate = true
  tree.nbytes_read += sizeof(T)
  AbstractImmediate(sizeof(T))
end

using X86Assembly: compressed_prefix_status

include("tree_folding.jl")
include("codegen.jl")

function run!(projection)
  mode = X86Assembly.processor_modes(true, true)
  n = 0
  #p = Progress(1616850)
  # Create a compressed structure from two bytes. We'll have the decoder work
  # from that.
  root = IOTreeRoot()
  tree = GenerativeIOTree(root, AbstractTrees.firststate(Leaves(root)), 1, false, 0)
  while true
    a = UInt16(read(tree, UInt8)) << 8
    b = read(tree, UInt8)
    compressed_prefix = a | b
    if !X86Assembly.validate_compressed_prefix(compressed_prefix_status(0b0,compressed_prefix,0))
        next!(tree, projection(tree, nothing)) || break
        continue
    end
    first_non_prefix_byte = read(tree, UInt8)
    prefix = compressed_prefix_status(0b0, compressed_prefix, first_non_prefix_byte)
    data = X86Assembly._parseOpc(tree, prefix, mode)
    # Create a tree of non-prefix bytes
    if !next!(tree, projection(tree, data))
        break
    end
    n += 1
  end
  fold!(root)
  function byte_reader(level)
       level == 1 ? :((prefix.flags >> 8) % UInt8) :
       level == 2 ? :(prefix.flags % UInt8) :
       level == 3 ? :(prefix.first_non_prefix_byte) :
                    :(read(io, UInt8))
  end
  code = generate_decoder_for_tree(root, byte_reader)
  thunk = quote
    function (io)
        prefix = X86Assembly.fast_compressed_prefix_scanner(io)
        $code
    end
  end
  f = eval(thunk)
  @show f
  println("Number of instruction variants: $n")
  (tree, f)
end
non_prefix_bytes(tree, data) = data == nothing ? -1 : tree.nbytes_read - 3
(tree, f) = run!(non_prefix_bytes)

function debug_tree(tree, io)
    prefix = X86Assembly.fast_compressed_prefix_scanner(io)
    bytes = [(prefix.flags >> 8)%UInt8, prefix.flags % UInt8, prefix.first_non_prefix_byte]
    AbstractTrees._print_tree(STDOUT, tree, 20; withinds = true) do buf, node, inds
        an = tree
        for (level, ind) in enumerate(inds)
            an = c = children(an)[ind]
            if level > length(bytes)
                push!(bytes, read(io, UInt8))
            end
            if !(bytes[level] in c.mask)
                showcompact(buf, node)
                return
            end
        end
        Base.print_with_color(:yellow, sprint(showcompact,node))
    end
end

buf = IOBuffer([0xf3,0x0f,0x58,0xed])
debug_tree(tree.tree, buf)
