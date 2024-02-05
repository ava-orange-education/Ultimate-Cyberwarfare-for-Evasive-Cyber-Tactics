# Usage
After using sRDI to convert into position-independent shellcode, use aes.py to produce encrypted shellcode

For rootkit dropper, use the x86 build tools instead

demon.bin is the shellcode produced by Havoc C2, the "beacon" of the Havoc Framework.

# Notice

Encryption using aes.py is mandatory, the shellcode by itself is easily detected. See original.cpp for the crypters.

