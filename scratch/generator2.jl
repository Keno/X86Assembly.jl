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
        next!(tree, "Bad prefix") || break
        continue
    end
    first_non_prefix_byte = read(tree, UInt8)
    prefix = compressed_prefix_status(0b0, compressed_prefix, first_non_prefix_byte)
    data = X86Assembly._parseOpc(tree, prefix, mode)
    # Create a tree of non-prefix bytes
    if !next!(tree, data == nothing ? "Invalid" : projection(tree, data))
        break
    end
    n += 1
  end
  @show Tree(root)
  fold!(root)
  @show Tree(root)
  println("Number of instruction variants: $n")
end
non_prefix_bytes(tree, data) = tree.nbytes_read - 3
run!(non_prefix_bytes)
