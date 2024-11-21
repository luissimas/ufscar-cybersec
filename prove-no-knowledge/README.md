# Prove No Knowledge

https://cor.team/posts/utctf-2021-prove-no-knowledge/
https://github.com/utisss/UTCTF-21/tree/main/crypto-prove-no-knowledge

## Running the solution

The target server is temporarily available at `cibersec-pnk.duckdns.org:4354`. Opening a TCP connection to the server should result in a response with an authentication challenge.

```sh
nc cibersec-pnk.duckdns.org 4354
```

Assuming that you have [uv](https://docs.astral.sh/uv/) installed, execute the following command to run the solution:

```sh
uv run run.py
```
