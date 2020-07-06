cdef extern from "evercrypt/MerkleTree.h":
    ctypedef struct merkle_tree:
        pass

    merkle_tree* mt_create(unsigned char* init1)

    void mt_insert(merkle_tree* tree, unsigned char* v1)

    void mt_get_root(merkle_tree* tree, unsigned char* rt)