#!/usr/bin/python3

from ctypes import c_int, c_ulonglong, POINTER, CDLL, byref

class Inspector():
    def __init__(self, libpath) -> None:
        self._lib = CDLL(libpath)

        self._lib.inspector_connect.restype = c_int
        self._lib.inspector_connect.argtypes = []

        self._lib.get_kslide.restype = c_ulonglong
        self._lib.get_kslide.argtypes = [c_int]

        self._lib.kbase.restype = c_ulonglong
        self._lib.kbase.argtypes = [c_int]

        self._lib.kread64.restype = None
        self._lib.kread64.argtypes = [c_int, c_ulonglong, POINTER(c_ulonglong)]

        self._lib.kwrite64.restype = None
        self._lib.kwrite64.argtypes = [c_int, c_ulonglong, c_ulonglong]

        self._lib.kcall.restype = c_ulonglong
        self._lib.kcall.argtypes = [c_int, c_ulonglong, c_int]

        self._sock = self.connect()
        self._kslide = None
        self._kbase = None

    def connect(self):
        return self._lib.inspector_connect()

    def kslide(self):
        if self._kslide == None:
            self._kslide = self._lib.get_kslide(self._sock)
        return self._kslide

    def kbase(self):
        if self._kbase == None:
            self._kbase = self._lib.kbase(self._sock)
        return self._kbase

    def current_proc(self):
        pass

    def current_task(self):
        pass

    def kread64(self, address):
        value = c_ulonglong(0)
        self._lib.kread64(self._sock, address, byref(value))
        return value.value

    def kwrite64(self, address, value):
        self._lib.kwrite64(self._sock, address, value)

    def kcopyin(self):
        pass

    def kcopyout(self):
        pass

    def kcall(self, f, n, *args):
        if n != len(args):
            print(f'[!] n and number of args is not equal! n : {n}, len(args) : {len(args)}')
            return 0xffffffffffffffff
        converted = [c_ulonglong(a) for a in args]
        return self._lib.kcall(self._sock, f, n, *converted)

def main():
    i = Inspector('build/libinspector.dylib')
    kslide = i.kslide()
    kbase  = i.kbase()
    print(f'kslide : 0x{kslide:016X}')
    print(f'kbase  : 0x{kbase:016X}')
    print(f'kread64({kbase:016X}) : {i.kread64(kbase):016X}')
    i.kcall(0x4141414141414141, 7, 0x4242424242424242, 0x4343434343434343, 0x4444444444444444, 0x4545454545454545, 0x4646464646464646, 0x4747474747474747, 0x4848484848484848)

if __name__ == '__main__':
    main()
