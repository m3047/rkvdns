# Configuration Guide

Deployment of _RKVDNS_ will follow a process of:

1. Making sure it works.
2. Configuring the environment so that it can be found in your deployed DNS environment.
3. Making sure it works as well as possible with your recursive / caching DNS servers.

Each on of these phases may require adjusting one or more configuration parameters differently than at another stage in
the process. In particular, _RKVDNS_ includes verbose capabilities which may not conform to what your DNS service expects but
which are useful for debugging problems.

Some features of the modern, as-built DNS environment may conflict with debugging features and optimal performance. In particular,
two common features of recursive / caching infrastructure are noted as seemingly optimized for the `A` / `AAAA` (address resolution)
use case and can cause problems for data use cases:

* **Query Retransmission** was originally performed on the order of _seconds_ (i.e. one or two seconds) before retrying / retransmitting
  a query. At the present time some recursing resolvers may retransmit within _tens of milliseconds_. The original RFCs suggest that
  authoritative services should respond to all
  received queries individually to assist the recursive resolver in determining the best authoritative server to use. In most cases there
  will only be one authoritative server (_RKVDNS_ instance) for an _RKVDNS_ zone. Furthermore, answering duplicate queries would require
  repeatedly querying the _Redis_ database and building individualized responses, which can be expensive especially when a large number
  of records are returned: responding to retransmissions individually is undesirable in the data use case. (Immediate use of TCP instead
  of polite fallback from UDP would be the recommended mitigation.)
* **Qname Minimization** is performed for the sake of privacy, in the sense of not broadcasting the entire question (which reveals
  a _Redis_ key) to every nameserver queried. In order to accomplish this, the recursing nameserver performs a game of "twenty questions" asking
  vague questions each of which elicits a little more information from the authoritative server(s) allowing it to proceed toward its
  resolution goal. In a "typical" deployment where two nameservers (a delegating authoritative server and an _RKVDNS_ instance) will need
  to be consulted this can cause **twice as many** DNS queries to be generated / answered than in the case where _qname minimization_ is
  not employed. Additionally an inconsistency in validation (non-functional requirements) is encountered: `strict` minimization employs
  some `NS` queries which will never be answered positively (there are no zones delegated from an _RKVDNS_ instance) however we cannot answer
  confidently with `NXDOMAIN` without performing a potentially expensive data lookup and so we have to answer with the more generic `ANSWER:0` + referral.

## Initial Deployment / Verification

During initial setup the questions you will be answering include:

* Does it talk to _Redis_?
* Does it retreve my keys / values?

## Environmental Setup

## Issues with Caching / Recursing Servers

