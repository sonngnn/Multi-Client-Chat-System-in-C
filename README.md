# RE216 — Multi-Client Chat System in C
**TCP/IP, POSIX sockets (`poll`), IRC-style users/channels, and P2P file transfer**

A from-scratch client/server chat application in C. It supports multi-client handling with a single process via `poll()`, user management (nicknames, who/whois), public and private messaging, channels (create/join/quit, multicast), and peer-to-peer file transfer negotiated by the server.

> Course project (RE216). Built incrementally across four milestones.

