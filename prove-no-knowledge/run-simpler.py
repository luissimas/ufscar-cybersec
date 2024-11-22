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

    # We can use an arbitrary r 
    r = 1
    # Pick a C such that C = g^r mod p
    c = pow(g, r, p)
    # Pick a C such that C = (g^r mod p) * (y^-1 mod p)
    mod_inv_c = pow(g, r, p) * pow(y, -1, p)

    # 256 rounds of authentication
    for round in range(1, 257):
        conn.recvline()
        # Send either c or mod_inv_c depending on the round
        if round % 2:
            conn.sendline(str(c).encode())
        else:
            conn.sendline(str(mod_inv_c).encode())
        conn.recvline()
        conn.sendline(str(r).encode())

        print(f"Round {round} completed.")

    # Receive the flag
    print(conn.recvall().decode())

if __name__ == "__main__":
    main()
