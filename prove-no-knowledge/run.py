from pwn import remote
from random import randrange

host = "cibersec-pnk.duckdns.org"
port = 4354

def main():
    # Open the server connection
    conn = remote(host, port)

    # Read the values for the given constants
    conn.recvuntil(b"g: ")
    g = int(conn.recvline())
    conn.recvuntil(b"p: ")
    p = int(conn.recvline())
    conn.recvuntil(b"y: ")
    y = int(conn.recvline())

    # 256 rounds of authentication
    for round in range(1, 257):
        # In the odd case we know that the server will ask for r
        if round % 2:
            # Generate a random r
            r = randrange(p)
            # Pick a C such that C = g^r mod p
            c = pow(g, r, p)
            conn.recvline()
            conn.sendline(str(c).encode())
            conn.recvline()
            conn.sendline(str(r).encode())
        # In the even case we know that the server will ask for (x + r) mod (p − 1)
        else:
            # Generate a random r
            r = randrange(p)
            # Pick a C such that C = (g^r mod p) * (y^-1 mod p)
            c = pow(g, r, p) * pow(y, -1, p)
            conn.recvline()
            conn.sendline(str(c).encode())
            conn.recvline()
            conn.sendline(str(r).encode())
        print(f"Round {round} completed.")

    # Receive the flag
    print(conn.recvall().decode())

if __name__ == "__main__":
    main()
