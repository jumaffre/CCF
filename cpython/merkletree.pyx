#!python
#cython: language_level=3

cimport merkletree

cdef class Tree:
    cdef merkletree.merkle_tree* tree_

    def __cinit__(self):
        self.tree_ = merkletree.mt_create("lala")

    def append(self, unsigned char* hash):
        merkletree.mt_insert(self.tree_, hash)

    def get_root(self):
        cdef unsigned char root[32]
        merkletree.mt_get_root(self.tree_, root)
        return root
