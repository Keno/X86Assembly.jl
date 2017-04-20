mutable struct PtrBuf <: IO
    ptr::Ptr{UInt8}
    sz::Csize_t
    pos::Csize_t
end
PtrBuf(ptr::Ptr{UInt8}, sz::Csize_t) = PtrBuf(ptr, sz, 0)
Base.eof(io::PtrBuf) = io.pos < io.sz
for T in (UInt8, UInt16, UInt32, UInt64)
    @eval Base.read(io::PtrBuf, ::Type{$T}) = unsafe_load(Ptr{$T}(io.ptr + io.pos))
end

#non_prefix_bytes(tree, data) = data == nothing ? -1 : tree.nbytes_read - 3
#(tree, f) = run!(non_prefix_bytes);

let f = f
  function decode_sizeof(data::Ptr{UInt8}, sz::Integer)
      f(PtrBuf(data, sz%Csize_t))
  end
end

code_llvm(decode_sizeof, Tuple{Ptr{UInt8}, Csize_t})
