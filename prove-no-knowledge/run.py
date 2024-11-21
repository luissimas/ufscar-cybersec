from pwn import remote
from sympy import mod_inverse
from random import randrange

host = "cibersec-pnk.duckdns.org"
port = 4354

def main():
    r = remote(host, port)
    r.recvuntil(b"g: ")
    g = int(r.recvline())
    r.recvuntil(b"p: ")
    p = int(r.recvline())
    r.recvuntil(b"y: ")
    y = int(r.recvline())

    rn = 1

    while rn < 257:
        if rn % 2:
            r.recvuntil(b"Send g^r mod p.")
            ran = randrange(p)
            r.sendline(str(pow(g, ran, p)).encode())
            r.recvuntil(b"Send r.")
            r.sendline(str(ran).encode())
        else:
            r.recvuntil(b"Send g^r mod p.")
            ran = randrange(p)
            C = (pow(g, ran, p) * mod_inverse(y, p)) % p
            r.sendline(str(C).encode())
            r.recvuntil(b"Send (x + r) mod (p - 1).")
            r.sendline(str(ran).encode())
        print(f"round {rn} passed")
        rn += 1
    r.interactive()

if __name__ == "__main__":
    main()
