# libssq

## What is it ?

libssq is a C library for querying Source servers.

## Why C ?

I wrote this library in C as a personal project in order to improve in this language I love.

## Manual

This protocol currently supported the three non-deprecated queries which are listed below:
- `A2S_INFO`: retrieves information about the server
- `A2S_PLAYER`: retrieves information about the players
- `A2S_RULES`: retrieves the server's rules

For more details about each query, please refer to Valve's [server queries documentation](https://developer.valvesoftware.com/wiki/Server_queries).

Before we can issue any query, we must initialize an `SSQHandle`. This opaque structure holds some data such as the timeouts for sending and receiving as well as the server's address obtained using `getaddrinfo`. It gets allocated on the heap and must be freed using the `ssq_free` function.

```c
const time_t timeout = 5000; // ms

SSQCode code; // return code

// initializes an SSQ handle for the target host example.com on
// port number 27015 with a sendto and recvfrom timeout of 5 sec
SSQHandle *ssq = ssq_init("example.com", 27015, timeout, &code);

if (code != SSQ_OK)
    // error handling

// ...

ssq_free(ssq);
```

Please refer to this repo's [wiki](https://github.com/BinaryAlien/libssq/wiki) for documentation about each function of the library.

From now on, we can change the address of an `SSQHandle` as well as its sendto and recvfrom timeouts by using `ssq_set_address` and `ssq_set_timeout` respectively.

```c
// sets the target address to "1.2.3.4" on port number 27015
if (!ssq_set_address("1.2.3.4", 27015))
    // error handling

ssq_set_timeout(ssq, SSQ_TIMEOUT_SEND, 5000);
ssq_set_timeout(ssq, SSQ_TIMEOUT_RECV, 5000);

// or ...

ssq_set_timeout(ssq, SSQ_TIMEOUT_SEND | SSQ_TIMEOUT_RECV, 5000);
```

Be sure to check out this repo's [wiki](https://github.com/BinaryAlien/libssq/wiki) for documentation about each function as well as the `example` folder which contains an example program which exploits each of the three queries.

## Dependencies

There are no dependencies for this project.
