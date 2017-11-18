# addressset.py -- btcrecover AddressSet library
# Copyright (C) 2017 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!

# (all optional futures for 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division

__version__ =  "0.1.3"

import struct, base64, io, mmap, ast, itertools, sys, gc, glob
from os import path


def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to an integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: int or long
    """
    bytes_len = len(bytes_rep)
    if bytes_len <= 4:
        return struct.unpack(">I", (4-bytes_len)*b"\0" + bytes_rep)[0]
    return long(base64.b16encode(bytes_rep), 16)


class AddressSet(object):
    """
    A set-like collection optimized for testing membership of Bitcoin addresses
    from their raw hash160 format with support for serializing to/from files
    """
    VERSION    = 1
    MAGIC      = b"seedrecover address database\r\n"  # file magic
    HEADER_LEN = 65536
    assert HEADER_LEN % mmap.ALLOCATIONGRANULARITY == 0

    def __init__(self, table_len, bytes_per_addr = 8, max_load = 0.75):
        """
        :param table_len: hash table size in count of addresses; must be a power of 2
        :type table_len: int
        :param bytes_per_addr: number of bytes of each address to store in the hash table
        :type bytes_per_addr: int
        :param max_load: max permissible load factor before an exception is raised
        :type max_load: float
        """
        if table_len < 1 or 1 << (table_len.bit_length()-1) != table_len:
            raise ValueError("table_len must be a positive power of 2")
        if not 1 <= bytes_per_addr <= 19:
            raise ValueError("bytes_per_addr must be between 1 and 19 inclusive")
        if not 0.0 < max_load < 1.0:
            raise ValueError("max_load must be between 0.0 and 1.0 exclusive")
        self._table_bytes    = table_len * bytes_per_addr         # len of hash table in bytes
        self._bytes_per_addr = bytes_per_addr                     # number of bytes per address to store
        self._null_addr      = b"\0" * bytes_per_addr             # all 0s is an empty hash table slot
        self._len            = 0                                  # count of addresses in the set
        self._max_len        = int(table_len * max_load)          # beyond this violates the load factor
        self._hash_bytes     = (table_len.bit_length() + 6) // 8  # number of bytes required for the mask
        self._hash_mask      = table_len - 1                      # mask used for the hash function
        self._data           = bytearray(self._table_bytes)       # the table itself
        self._dbfile         = None                               # file object, its .name is req'd for pickling
        self._mmap_access    = None                               # also required for pickling
        self.last_filenum    = None                               # will be serialized if set by the user
        if self._bytes_per_addr + self._hash_bytes > 20:
            raise ValueError("not enough bytes for both hashing and storage; "
                             "reduce either the bytes_per_addr or table_len")

    def __getstate__(self):
        # mmaps can't be pickled, so save only what's needed to recreate the object from scratch later
        if isinstance(self._data, mmap.mmap):
            return {"dbfilename": self._dbfile.name, "mmap_access": self._mmap_access}
        else:
            return self.__dict__

    def __setstate__(self, state):
        # If the object contained an mmap, recreate it from scratch
        if "dbfilename" in state:
            new = self.fromfile(open(state["dbfilename"], "r+b" if state["mmap_access"]==mmap.ACCESS_WRITE else "rb"),
                                mmap_access=state["mmap_access"], preload=False)
            self.__dict__ = new.__dict__.copy()
            new._dbfile = new._data = None  # ensure new's __del__() doesn't close() anything
        else:
            self.__dict__ = state

    def  __len__(self):
        return self._len

    def __contains__(self, address):
        return self._find(address) is True

    def add(self, address):
        """Adds the address to the set

        :param address: the address in hash160 (length 20) format to add
        :type address: bytes or str
        """
        pos = self._find(address)
        if pos is not True:
            bytes_to_add = address[ -(self._bytes_per_addr+self._hash_bytes) : -self._hash_bytes]
            if bytes_to_add.endswith(self._null_addr):
                return  # ignore these invalid addresses
            if self._len >= self._max_len:
                raise ValueError("addition to AddressSet exceeds load factor")
            self._data[pos : pos+self._bytes_per_addr] = bytes_to_add
            self._len += 1

    # Hash table with open addressing and linear probing:
    # The hash function is simply some of the address's least significant bits (since
    # most addresses are random hashes, this and linear probing should be sufficient).
    # To further save space, only the least significant _bytes_per_addr (typ. 8) bytes--
    # excluding those bytes already used for the "hash" above--are stored in the table,
    # causing different addresses to appear to be the same and false positives, however
    # (with high probability) only for invalid addresses (those w/o private keys).
    def _find(self, addr_to_find):
        pos = self._bytes_per_addr * (bytes_to_int(addr_to_find[ -self._hash_bytes :]) & self._hash_mask)
        while True:
            cur_addr = self._data[pos : pos+self._bytes_per_addr]
            if cur_addr == self._null_addr:
                return pos  # the position this element could be inserted at
            if len(addr_to_find) > self._bytes_per_addr:
                addr_to_find = addr_to_find[ -(self._bytes_per_addr+self._hash_bytes) : -self._hash_bytes]
            if cur_addr == addr_to_find:
                return True
            pos += self._bytes_per_addr  # linear probing
            if pos >= self._table_bytes:
                pos = 0

    def __iter__(self):
        """Iterates over the set returning the bytes_per_addr stored for each address
        """
        pos = 0
        while pos < self._table_bytes:
            cur_addr = self._data[pos : pos+self._bytes_per_addr]
            if cur_addr != self._null_addr:
                yield cur_addr
            pos += self._bytes_per_addr

    def __reversed__(self):
        pos = self._table_bytes - self._bytes_per_addr
        while pos >= 0:
            cur_addr = self._data[pos : pos+self._bytes_per_addr]
            if cur_addr != self._null_addr:
                yield cur_addr
            pos -= self._bytes_per_addr

    @staticmethod
    def _remove_nonheader_attribs(attrs):
        del attrs["_data"], attrs["_dbfile"], attrs["_mmap_access"]

    def _header(self):
        # Construct a 64K header with the file magic, this object's attributes, plus the version
        header_dict = self.__dict__.copy()
        self._remove_nonheader_attribs(header_dict)
        header_dict["version"] = self.VERSION
        header = repr(header_dict) + b"\r\n"
        assert ast.literal_eval(header) == header_dict
        header = self.MAGIC + header
        header_len = len(header)
        assert header_len < self.HEADER_LEN
        return header + b"\0" * (self.HEADER_LEN - header_len)  # appends at least one nul

    def tofile(self, dbfile):
        """Save the address set to a file

        :param dbfile: an open file object where the set is saved (overwriting it)
        :type dbfile: io.FileIO or file
        """
        if dbfile.tell() % mmap.ALLOCATIONGRANULARITY != 0:
            print("AddressSet: warning: if header position in file isn't a multiple of {}, it probably can't be loaded with fromfile()"
                  .format(mmap.ALLOCATIONGRANULARITY), file=sys.stderr)
        if "b" not in dbfile.mode:
            raise ValueError("must open file in binary mode")
        # Windows Python 2 file objects can't handle writes >= 4GiB. Objects returned
        # by io.open() work around this issue, see https://bugs.python.org/issue9611
        if not isinstance(dbfile, io.BufferedIOBase) and self._table_bytes >= 1 << 32:
            raise ValueError("must open file with io.open if size >= 4GiB")
        dbfile.truncate(dbfile.tell() + self.HEADER_LEN + self._table_bytes)
        dbfile.write(self._header())
        dbfile.write(self._data)

    @classmethod
    def fromfile(cls, dbfile, mmap_access = mmap.ACCESS_READ, preload = True):
        """Load the address set from a file

        :param dbfile: an open file object from which the set is loaded;
                       it will be closed by AddressSet when no longer needed
        :type dbfile: io.FileIO or file
        :param mmap_access: mmap.ACCESS_READ, .ACCESS_WRITE, or .ACCESS_COPY
        :type mmap_access: int
        :param preload: True to preload the entire address set, False to load on demand
        :type preload: bool
        """
        if "b" not in dbfile.mode:
            raise ValueError("must open file in binary mode")
        header_pos = dbfile.tell()
        if header_pos % mmap.ALLOCATIONGRANULARITY != 0:
            raise ValueError("header position in file must be a multiple of {}".format(mmap.ALLOCATIONGRANULARITY))
        #
        # Read in the header safely (ast.literal_eval() is safe for untrusted data)
        header = dbfile.read(cls.HEADER_LEN)
        if not header.startswith(cls.MAGIC):
            raise ValueError("unrecognized file format (invalid magic)")
        magic_len  = len(cls.MAGIC)
        config_end = header.find(b"\0", magic_len, cls.HEADER_LEN)
        assert config_end > 0
        config = ast.literal_eval(header[magic_len:config_end])
        if config["version"] != cls.VERSION:
            raise ValueError("can't load address database version {} (only supports {})"
                             .format(config["version"], cls.VERSION))
        #
        # Create an AddressSet object and replace its attributes
        self = cls(1)  # (size is irrelevant since it's getting replaced)
        cls._remove_nonheader_attribs(self.__dict__)
        for attr in self.__dict__.keys():  # only load expected attributes from untrusted data
            self.__dict__[attr] = config[attr]
        self._mmap_access = mmap_access
        #
        # The hash table is memory-mapped directly from the file instead of being loaded
        self._data = mmap.mmap(dbfile.fileno(), self._table_bytes, access=mmap_access,
                                offset= header_pos + cls.HEADER_LEN)
        if mmap_access == mmap.ACCESS_WRITE:
            dbfile.seek(header_pos)  # prepare for writing an updated header in close()
        else:
            dbfile.close()
        self._dbfile = dbfile
        #
        # Most of the time it makes sense to load the file serially instead of letting
        # the OS load each page as it's touched in random order, especially with HDDs;
        # reading a byte from each page is sufficient (CPython doesn't optimize this away)
        if preload:
            for i in xrange(self._table_bytes // mmap.PAGESIZE):
                self._data[i * mmap.PAGESIZE]
        #
        return self

    def close(self, flush = True):
        if self._dbfile:                 # if present, self._data is an mmap
            if not self._dbfile.closed:  # if not closed, the mmap was opened in write/update mode
                self._dbfile.write(self._header())  # update the header
                self._dbfile.close()
                if flush:
                    self._data.flush()
            self._data.close()
            self._dbfile = None
        elif isinstance(self._data, bytearray) and self._data:
            self._data = bytearray()
        if flush:
            gc.collect()

    def __del__(self):
        if hasattr(self, "_dbfile"):
            self.close(flush=False)


# Decodes a Bitcoin-style variable precision integer and
# returns a tuple containing its value and incremented offset
def varint(data, offset):
    b = ord(data[offset])
    if b <= 252:
        return b, offset + 1
    if b == 253:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    if b == 254:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    if b == 255:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9
    assert False


def create_address_db(dbfilename, blockdir, update = False, progress_bar = True):
    """Creates an AddressSet database and saves it to a file

    :param dbfilename: the file name where the database is saved (overwriting it)
    :type dbfilename: str
    :param blockdir: the data directory where the Bitcoin block files reside
    :type blockdir: str
    :param update: if True, the existing database file is updated from new txs
    :type update: bool
    :param progress_bar: True to enable the progress bar
    :type progress_bar: bool
    """

    for filename in glob.iglob(path.join(blockdir, "blk*.dat")):
        if path.isfile(filename): break
    else:
        raise ValueError("no block files exist in blocks directory '{}'".format(blockdir))

    if update:
        print("Loading address database ...")
        address_set   = AddressSet.fromfile(open(dbfilename, "r+b"), mmap_access=mmap.ACCESS_WRITE)
        first_filenum = address_set.last_filenum
        print()
    else:
        first_filenum = 0

    filename = "blk{:05}.dat".format(first_filenum)
    if not path.isfile(path.join(blockdir, filename)):
        raise ValueError("first block file '{}' doesn't exist in blocks directory '{}'".format(filename, blockdir))

    if not update:
        # Open the file early to make sure we can, but don't overwrite it yet
        # (see AddressSet.tofile() for why io.open() instead of open() is used)
        try:
            dbfile = io.open(dbfilename, "r+b")
        except IOError:
            dbfile = io.open(dbfilename, "wb")
        # With the default bytes_per_addr and max_load, this allocates
        # about 4 GiB which is room for a little over 400 million addresses
        address_set = AddressSet(1 << 29)

    if progress_bar:
        try:
            import progressbar
        except ImportError:
            progress_bar = False

    if progress_bar:
        print("Parsing block files ...")
        for filenum in itertools.count(first_filenum):
            filename = path.join(blockdir, "blk{:05}.dat".format(filenum))
            if not path.isfile(filename):
                break
        progress_label = progressbar.FormatLabel(" {:11,} addrs. %(elapsed)s, ".format(len(address_set)))
        progress_bar = progressbar.ProgressBar(maxval=filenum-first_filenum, widgets=[
            progressbar.SimpleProgress(), " ",
            progressbar.Bar(left="[", fill="-", right="]"),
            progress_label,
            progressbar.ETA()
        ])
        progress_bar.start()
    else:
        print("Block file   Address count")
        print("------------ -------------")
        # e.g. blk00943.dat   255,212,706

    for filenum in itertools.count(first_filenum):
        filename = path.join(blockdir, "blk{:05}.dat".format(filenum))
        if not path.isfile(filename):
            break
        address_set.last_filenum = filenum

        with open(filename, "rb") as blockfile:
            if not progress_bar:
                print(path.basename(filename), end=" ")

            header = blockfile.read(8)  # read in the magic and remaining (after these 8 bytes) block length
            while len(header) == 8 and header[4:] != b"\0\0\0\0":
                assert header[:4] == b"\xf9\xbe\xb4\xd9"                        # magic

                block = blockfile.read(struct.unpack_from("<I", header, 4)[0])  # read in the rest of the block
                tx_count, offset = varint(block, 80)                            # skips 80 bytes of header
                for tx_num in xrange(tx_count):
                    offset += 4                                                 # skips 4-byte tx version
                    is_bip144 = block[offset] == b"\0"                          # bip-144 marker
                    if is_bip144:
                        offset += 2                                             # skips 1-byte marker & 1-byte flag
                    txin_count, offset = varint(block, offset)
                    for txin_num in xrange(txin_count):
                        sigscript_len, offset = varint(block, offset + 36)      # skips 32-byte tx id & 4-byte tx index
                        offset += sigscript_len + 4                             # skips sequence number & sigscript
                    txout_count, offset = varint(block, offset)
                    for txout_num in xrange(txout_count):
                        pkscript_len, offset = varint(block, offset + 8)        # skips 8-byte satoshi count

                        # If this is a P2PKH script (OP_DUP OP_HASH160 PUSH(20) <20 address bytes> OP_EQUALVERIFY OP_CHECKSIG)
                        if pkscript_len == 25 and block[offset:offset+3] == b"\x76\xa9\x14" and block[offset+23:offset+25] == b"\x88\xac":
                            # Add the discovered address to the address set
                            address_set.add(block[offset+3:offset+23])

                        offset += pkscript_len                                  # advances past the pubkey script
                    if is_bip144:
                        for txin_num in xrange(txin_count):
                            stackitem_count, offset = varint(block, offset)
                            for stackitem_num in xrange(stackitem_count):
                                stackitem_len, offset = varint(block, offset)
                                offset += stackitem_len                         # skips this stack item
                    offset += 4                                                 # skips the 4-byte locktime
                header = blockfile.read(8)  # read in the next magic and remaining block length

        if progress_bar:
            progress_label.format = " {:11,} addrs. %(elapsed)s, ".format(len(address_set))  # updates address count
            nextval = progress_bar.currval + 1
            if nextval > progress_bar.maxval:  # can happen if the bitcoin client is left running
                progress_bar.maxval = nextval
            progress_bar.update(nextval)
        else:
            print("{:13,}".format(len(address_set)))

    if progress_bar:
        progress_bar.widgets.pop()  # remove the ETA
        progress_bar.finish()
    if update:
        print("\nSaving changes to address database ...")
        address_set.close()
    else:
        print("\nSaving address database ...")
        dbfile.truncate(0)
        address_set.tofile(dbfile)
        dbfile.close()

    print("\nDone.")
