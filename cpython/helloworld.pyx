#!python
#cython: language_level=3

cdef extern from "helloworld.h":
    void hello(const char *name)

def py_hello(name: bytes) -> None:
    hello(name)